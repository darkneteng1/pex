// Package pex is a toolkit for implementing a peer exchange system
package pex

import (
    "errors"
    "fmt"
    "github.com/op/go-logging"
    "io"
    "io/ioutil"
    "log"
    "math/rand"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
    "time"
)

var (
    // Filename for disk-cached peers
    PeerDatabaseFilename = "peers.txt"
    // Filename for disk-cached blacklisted peers
    BlacklistedDatabaseFilename = "blacklisted_peers.txt"
    // Number of peers to send in response to a GetPeers request
    PeerReplyCount = 20
    // Returned when the PeerList is at a maximum
    PeerListFullError = errors.New("Peer list full")
    // Returned when an address appears malformed
    InvalidAddressError = errors.New("Invalid address")
    // Returned when attempting to add a blacklisted peer
    BlacklistedAddressError = errors.New("Blacklisted address")
    // How often to updated expired entries in the blacklist
    UpdateBlacklistRate = time.Second * 30
    // Logging. See http://godoc.org/github.com/op/go-logging for
    // instructions on how to include this log's output
    logger = logging.MustGetLogger("pex")
    // Default rng
    rnum = rand.New(rand.NewSource(time.Now().Unix()))
    // For removing inadvertent whitespace from addresses
    whitespaceFilter = regexp.MustCompile("\\s")
)

// Returns true if ip_port is a valid ip:host
func ValidateIPString(ip_port string) bool {
    ip_port = whitespaceFilter.ReplaceAllString(ip_port, "")
    pts := strings.Split(ip_port, ":")
    if len(pts) != 2 {
        return false
    }
    ip := net.ParseIP(pts[0])
    if ip == nil || !ip.IsGlobalUnicast() {
        return false
    }
    port, err := strconv.ParseUint(pts[1], 10, 16)
    if err != nil || port < 1024 {
        return false
    }
    return true
}

// PeerState represents a known peer
type PeerState struct {
    Addr     string // An address of the form ip:port
    LastSeen int64  // Unix timestamp when this peer was last seen
}

// Returns a *PeerState initialised by an address string of the form ip:port
func NewPeerState(address string) *PeerState {
    p := &PeerState{Addr: address}
    p.Seen()
    return p
}

// Mark the peer as seen
func (self *PeerState) Seen() {
    self.LastSeen = time.Now().Unix()
}

func (self *PeerState) String() string {
    return self.Addr
}

// BlacklistEntry records when an address was blacklisted and how long
// it should be blacklisted for. A duration of 0 is permanent.
type BlacklistEntry struct {
    Start    time.Time
    Duration time.Duration
}

// Returns the time.Time the BlacklistEntry expires
func (b BlacklistEntry) ExpiresAt() time.Time {
    return b.Start.Add(b.Duration)
}

func NewBlacklistEntry(duration time.Duration) BlacklistEntry {
    return BlacklistEntry{Start: time.Now().UTC(), Duration: duration}
}

// PeerList manages a set of known peers and controls peer acquisition
type PeerList struct {
    // A list of urls that point to a newline delimited list of peer addresses
    BootstrapEndpoints []string
    // All known peers
    Peers map[string]*PeerState
    // Ignored peers
    BlacklistedPeers map[string]BlacklistEntry
    maxPeers         int
}

func NewPeerList(max_peers int) *PeerList {
    return &PeerList{
        BootstrapEndpoints: make([]string, 0),
        Peers:              make(map[string]*PeerState, max_peers),
        BlacklistedPeers:   make(map[string]BlacklistEntry, 0),
        maxPeers:           max_peers,
    }
}

// Removes expired peers from the blacklist.
func (self *PeerList) UpdateBlacklist() {
    now := time.Now().UTC()
    for p, b := range self.BlacklistedPeers {
        if b.ExpiresAt().Before(now) {
            delete(self.BlacklistedPeers, p)
        }
    }
}

// Mark a peer for the blacklist
func (self *PeerList) Blacklist(addr string, duration time.Duration) {
    if ValidateIPString(addr) {
        self.RemovePeer(addr)
        self.BlacklistedPeers[addr] = NewBlacklistEntry(duration)
        logger.Debug("Blacklisting peer %s for %s\n", addr, duration.String())
    } else {
        logger.Warning("Attempted to blacklist invalid IP:Port %s\n", addr)
    }
}

// Returns whether an address is blacklisted
func (self *PeerList) IsBlacklisted(addr string) bool {
    _, is := self.BlacklistedPeers[addr]
    return is
}

// Loads a blacklisted peer with a preset start time
func (self *PeerList) loadBlacklistedPeer(addr string, start time.Time,
    duration time.Duration) {
    self.RemovePeer(addr)
    self.BlacklistedPeers[addr] = BlacklistEntry{
        Start:    start,
        Duration: duration,
    }
}

// Sets the maximum number of peers for the list. An existing list will be
// truncated. A maximum of 0 is treated as unlimited
func (self *PeerList) SetMaxPeers(max int) {
    if max < 0 {
        log.Panic("Invalid max peers")
    }
    self.maxPeers = max
    if max == 0 {
        return
    }
    peers := make(map[string]*PeerState, max)
    ct := 0
    for addr, peer := range self.Peers {
        if ct >= max {
            break
        }
        peers[addr] = peer
        ct++
    }
    self.Peers = peers
}

// Adds a url endpoint to the list of bootstrap endpoints
func (self *PeerList) AddBootstrapEndpoint(endpoint string) {
    self.BootstrapEndpoints = append(self.BootstrapEndpoints, endpoint)
}

// Adds peers retrieved from bootstrap nodes and returns the number of peers
// added or updated.
func (self *PeerList) BootstrapPeers() (added int) {
    for _, endpoint := range self.BootstrapEndpoints {
        peers, err := extractPeersFromHttp(endpoint)
        if err != nil {
            continue
        }
        for _, peer := range peers {
            _, err := self.AddPeer(peer)
            if err == nil {
                added += 1
            }
        }
    }
    return
}

// Requests peers sequentially from a list of connections.
// Your message's Send() method should spawn a goroutine if one is desired
func (self *PeerList) RequestPeers(connections []net.Conn,
    message_ctor GetPeersMessageConstructor) {
    if !self.Full() {
        for _, conn := range connections {
            m := message_ctor()
            m.Send(conn)
        }
    }
}

// Adds peers received from an incoming GivePeersMessage
func (self *PeerList) RespondToGivePeersMessage(m GivePeersMessage) {
    for _, p := range m.GetPeers() {
        self.AddPeer(p)
    }
}

// Sends a GivePeersMessage in response to an incoming GetPeersMessage
func (self *PeerList) RespondToGetPeersMessage(conn net.Conn,
    message_ctor GivePeersMessageConstructor) GivePeersMessage {
    peers := self.RandomPeers(PeerReplyCount)
    if len(peers) == 0 {
        return nil
    }
    m := message_ctor(peers)
    m.Send(conn)
    return m
}

// Removes peers that haven't been seen in time_ago seconds
func (self *PeerList) ClearOldPeers(time_ago time.Duration) {
    t := time.Now().Unix()
    for addr, peer := range self.Peers {
        if t-peer.LastSeen > int64(time_ago) {
            delete(self.Peers, addr)
        }
    }
}

// Returns the string addresses of all peers
func (self *PeerList) GetPeerAddresses() []string {
    keys := make([]string, 0, len(self.Peers))
    for key, _ := range self.Peers {
        keys = append(keys, key)
    }
    return keys
}

// Returns the string addresses of all blacklisted peers
func (self *PeerList) GetBlacklistedPeerAddresses() []string {
    keys := make([]string, 0, len(self.BlacklistedPeers))
    for key, _ := range self.BlacklistedPeers {
        keys = append(keys, key)
    }
    return keys
}

// Returns a random peer
func (self *PeerList) RandomPeer() *PeerState {
    keys := self.GetPeerAddresses()
    if len(keys) == 0 {
        return nil
    }
    index := rnum.Intn(len(keys))
    return self.Peers[keys[index]]
}

// Returns count random peers, or all of the peers, whichever is lower.
// If count is 0, all of the peers are returned, shuffled.
func (self *PeerList) RandomPeers(count int) []*PeerState {
    keys := self.GetPeerAddresses()
    if len(keys) == 0 {
        return nil
    }
    max := count
    if count == 0 || count > len(keys) {
        max = len(keys)
    }
    peers := make([]*PeerState, 0, max)
    perm := rand.Perm(len(keys))
    for _, i := range perm[:max] {
        peers = append(peers, self.Peers[keys[i]])
    }
    return peers
}

// Removes a peer from the peer list
func (self *PeerList) RemovePeer(addr string) {
    delete(self.Peers, addr)
}

// Adds a peer to the peer list, given an address. If the peer list is
// full, PeerListFullError is returned */
func (self *PeerList) AddPeer(address string) (*PeerState, error) {
    if !ValidateIPString(address) {
        return nil, InvalidAddressError
    }
    _, blacklisted := self.BlacklistedPeers[address]
    if blacklisted {
        return nil, BlacklistedAddressError
    }
    peer := self.Peers[address]
    if peer != nil {
        peer.Seen()
        return peer, nil
    } else if self.Full() {
        return nil, PeerListFullError
    } else {
        peer = NewPeerState(address)
        self.Peers[peer.Addr] = peer
        return peer, nil
    }
}

// Returns true if no more peers can be added
func (self *PeerList) Full() bool {
    return self.maxPeers > 0 && len(self.Peers) >= self.maxPeers
}

// Returns the number of peers in the peer list
func (self *PeerList) Count() int {
    return len(self.Peers)
}

// Loads a peer database file
func (self *PeerList) loadDatabase(dir, filename string) ([]string, error) {
    fn := filepath.Join(dir, filename)
    f, err := os.Open(fn)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    info, err := f.Stat()
    if err != nil {
        return nil, err
    }
    data := make([]byte, info.Size())
    _, err = f.Read(data)
    if err != nil && err != io.EOF {
        return nil, err
    }
    return strings.Split(string(data), "\n"), nil
}

// Loads a newline delimited list of addresses from
// "<dir>/<PeerDatabaseFilename>"
func (self *PeerList) LoadPeerDatabase(dir string) error {
    peers, err := self.loadDatabase(dir, PeerDatabaseFilename)
    if err != nil {
        return err
    }
    for _, addr := range peers {
        self.AddPeer(addr)
    }
    return nil
}

// Loads a newline delimited list of addresses from
// <dir>/<BlacklistedDatabaseFilename> into the BlacklistedPeers index
func (self *PeerList) LoadBlacklistedPeerDatabase(dir string) error {
    lines, err := self.loadDatabase(dir, BlacklistedDatabaseFilename)
    if err != nil {
        return err
    }
    logInvalid := func(line, msg string) {
        logger.Warning("Invalid blacklist db entry: \"%s\"\n", line)
        logger.Warning("Reason: %s\n", msg)
    }
    for _, line := range lines {
        pts := strings.Split(line, " ")
        if len(pts) != 3 {
            logInvalid(line, "Not of form <addr> <start> <duration>")
            continue
        }
        addr := whitespaceFilter.ReplaceAllString(pts[0], "")
        if addr == "" {
            logInvalid(line, "Empty address")
            continue
        }
        start, err := strconv.ParseInt(pts[1], 10, 64)
        if err != nil {
            logInvalid(line, fmt.Sprintf("Invalid start time: %v", err))
            continue
        }
        duration, err := strconv.ParseInt(pts[1], 10, 64)
        if err != nil {
            logInvalid(line, fmt.Sprintf("Invalid duration: %v", err))
            continue
        }
        self.loadBlacklistedPeer(addr, time.Unix(start, 0),
            time.Duration(duration))
    }
    // Clear out any expired blacklist entries
    self.UpdateBlacklist()
    return nil
}

// Loads both the normal peer and blacklisted peer databases
func (self *PeerList) LoadDatabase(dir string) error {
    err := self.LoadPeerDatabase(dir)
    if err == nil {
        err = self.LoadBlacklistedPeerDatabase(dir)
    }
    return err
}

// Saves known peers to disk as a newline delimited list of addresses to
// <dir><PeerDatabaseFilename>
func (self *PeerList) SavePeerDatabase(dir string) error {
    filename := PeerDatabaseFilename
    fn := filepath.Join(dir, filename+".tmp")
    f, err := os.Create(fn)
    if err != nil {
        return err
    }
    defer f.Close()
    s := strings.Join(self.GetPeerAddresses(), "\n") + "\n"
    _, err = f.WriteString(s)
    if err != nil {
        return err
    }
    return os.Rename(fn, filepath.Join(dir, filename))
}

// Saves blacklisted peers to disk as a newline delimited list of addresses to
// <dir><PeerDatabaseFilename>
func (self *PeerList) SaveBlacklistedPeerDatabase(dir string) error {
    filename := BlacklistedDatabaseFilename
    fn := filepath.Join(dir, filename+".tmp")
    f, err := os.Create(fn)
    if err != nil {
        return err
    }
    defer f.Close()
    entries := make([]string, 0, len(self.BlacklistedPeers))
    for addr, entry := range self.BlacklistedPeers {
        // Skip empty addresses
        addr = whitespaceFilter.ReplaceAllString(addr, "")
        if addr == "" {
            continue
        }
        duration := entry.Duration.Nanoseconds() / 1e9
        line := fmt.Sprintf("%s %d %d", addr, entry.Start.Unix(), duration)
        entries = append(entries, line)
    }
    s := strings.Join(entries, "\n") + "\n"
    _, err = f.WriteString(s)
    if err != nil {
        return err
    }
    return os.Rename(fn, filepath.Join(dir, filename))
}

// Saves both the normal peer and blacklisted peer databases
func (self *PeerList) SaveDatabase(dir string) error {
    err := self.SavePeerDatabase(dir)
    if err == nil {
        err = self.SaveBlacklistedPeerDatabase(dir)
    }
    return err
}

type _e func(string) ([]string, error)

// Requests and parses a newline delimited list of peers from an http endpoint
var extractPeersFromHttp _e = func(url string) (peers []string, err error) {
    resp, err := http.Get(url)
    if err != nil {
        return
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return
    }
    _peers := strings.Split(string(body), "\n")
    peers = make([]string, 0)
    for _, p := range _peers {
        if p != "" {
            peers = append(peers, p)
        }
    }
    return
}

/* Binary protocol messages */

// A request for more peers
type GetPeersMessage interface {
    // This should result in the message being sent to the connection
    Send(net.Conn) error
}

// A response to GetPeersMessage, or unsolicited
type GivePeersMessage interface {
    // This should return an array of remote addresses
    GetPeers() []string
    // This should result in the message being sent to the connection
    Send(net.Conn) error
}

// A function that returns an instance that satisfies the GetPeersMessage
// interface
type GetPeersMessageConstructor func() GetPeersMessage

// A function that returns an instance that satisfies the GivePeersMessage
// interface
type GivePeersMessageConstructor func([]*PeerState) GivePeersMessage
