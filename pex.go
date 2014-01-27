// Package pex is a toolkit for implementing a peer exchange system
package pex

import (
    "errors"
    "fmt"
    "github.com/op/go-logging"
    "io"
    "log"
    "math/rand"
    "net"
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
    // Returned when the Pex is at a maximum
    PeerlistFullError = errors.New("Peer list full")
    // Returned when an address appears malformed
    InvalidAddressError = errors.New("Invalid address")
    // Returned when attempting to add a blacklisted peer
    BlacklistedAddressError = errors.New("Blacklisted address")
    // How often to updated expired entries in the blacklist
    RefreshBlacklistRate = time.Second * 30
    // Logging. See http://godoc.org/github.com/op/go-logging for
    // instructions on how to include this log's output
    logger = logging.MustGetLogger("pex")
    // Default rng
    rnum = rand.New(rand.NewSource(time.Now().Unix()))
    // For removing inadvertent whitespace from addresses
    whitespaceFilter = regexp.MustCompile("\\s")
)

// Returns true if ipPort is a valid ip:host string
func ValidateAddress(ipPort string) bool {
    ipPort = whitespaceFilter.ReplaceAllString(ipPort, "")
    pts := strings.Split(ipPort, ":")
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

// Peer represents a known peer
type Peer struct {
    Addr     string    // An address of the form ip:port
    LastSeen time.Time // Unix timestamp when this peer was last seen
}

// Returns a *Peer initialised by an address string of the form ip:port
func NewPeer(address string) *Peer {
    p := &Peer{Addr: address}
    p.Seen()
    return p
}

// Mark the peer as seen
func (self *Peer) Seen() {
    self.LastSeen = time.Now().UTC()
}

func (self *Peer) String() string {
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

// Blacklist is a map of addresses to BlacklistEntries
type Blacklist map[string]BlacklistEntry

// Saves blacklisted peers to disk as a newline delimited list of addresses to
// <dir><PeerDatabaseFilename>
func (self Blacklist) Save(dir string) error {
    filename := BlacklistedDatabaseFilename
    fn := filepath.Join(dir, filename+".tmp")
    f, err := os.Create(fn)
    if err != nil {
        return err
    }
    defer f.Close()
    entries := make([]string, 0, len(self))
    for addr, entry := range self {
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

// Removes expired peers from the blacklist.
func (self Blacklist) Refresh() {
    now := time.Now().UTC()
    for p, b := range self {
        if b.ExpiresAt().Before(now) {
            delete(self, p)
        }
    }
}

// Returns the string addresses of all blacklisted peers
func (self Blacklist) GetAddresses() []string {
    keys := make([]string, 0, len(self))
    for key, _ := range self {
        keys = append(keys, key)
    }
    return keys
}

// Loads a newline delimited list of addresses from
// <dir>/<BlacklistedDatabaseFilename> into the Blacklist index
func LoadBlacklist(dir string) (Blacklist, error) {
    lines, err := readLines(filepath.Join(dir, BlacklistedDatabaseFilename))
    blacklist := make(Blacklist)
    if os.IsNotExist(err) {
        return blacklist, nil
    }
    if err != nil {
        return nil, err
    }
    logInvalid := func(line, msg string) {
        logger.Warning("Invalid blacklist db entry: \"%s\"", line)
        logger.Warning("Reason: %s", msg)
    }
    for _, line := range lines {
        line = whitespaceFilter.ReplaceAllString(line, " ")
        pts := make([]string, 0, 3)
        for _, p := range strings.Split(line, " ") {
            if p != "" {
                pts = append(pts, p)
            }
        }
        if len(pts) != 3 {
            logInvalid(line, "Not of form $ADDR $BANSTART $BANDURATION")
            continue
        }
        addr := whitespaceFilter.ReplaceAllString(pts[0], "")
        if addr == "" || strings.HasPrefix(addr, "#") {
            continue
        }
        if !ValidateAddress(addr) {
            logInvalid(line, fmt.Sprintf("Invalid IP:Port %s", addr))
            continue
        }
        start, err := strconv.ParseInt(pts[1], 10, 64)
        if err != nil {
            logInvalid(line, fmt.Sprintf("Invalid start time: %v", err))
            continue
        }
        duration, err := strconv.ParseInt(pts[2], 10, 64)
        if err != nil {
            logInvalid(line, fmt.Sprintf("Invalid duration: %v", err))
            continue
        }
        blacklist[addr] = BlacklistEntry{
            Start:    time.Unix(start, 0).UTC(),
            Duration: time.Duration(duration) * time.Second,
        }
    }
    blacklist.Refresh()
    return blacklist, nil
}

// Peerlist is a map of addresses to *PeerStates
type Peerlist map[string]*Peer

// Returns the string addresses of all peers
func (self Peerlist) GetAddresses() []string {
    keys := make([]string, 0, len(self))
    for key, _ := range self {
        keys = append(keys, key)
    }
    return keys
}

// Removes peers that haven't been seen in time_ago seconds
func (self Peerlist) ClearOld(time_ago time.Duration) {
    t := time.Now().UTC()
    for addr, peer := range self {
        if t.Sub(peer.LastSeen) > time_ago {
            delete(self, addr)
        }
    }
}

// Saves known peers to disk as a newline delimited list of addresses to
// <dir><PeerDatabaseFilename>
func (self Peerlist) Save(dir string) error {
    entries := make([]string, 0)
    for _, p := range self {
        entry := fmt.Sprintf("%s %d", p.Addr, p.LastSeen.Unix())
        entries = append(entries, entry)
    }
    s := strings.Join(entries, "\n") + "\n"

    filename := PeerDatabaseFilename
    fn := filepath.Join(dir, filename+".tmp")
    f, err := os.Create(fn)
    if err != nil {
        return err
    }
    defer f.Close()
    _, err = f.WriteString(s)
    if err != nil {
        return err
    }
    return os.Rename(fn, filepath.Join(dir, filename))
}

// Returns n random peers, or all of the peers, whichever is lower.
// If count is 0, all of the peers are returned, shuffled.
func (self Peerlist) Random(count int) []*Peer {
    keys := self.GetAddresses()
    if len(keys) == 0 {
        return make([]*Peer, 0)
    }
    max := count
    if count == 0 || count > len(keys) {
        max = len(keys)
    }
    peers := make([]*Peer, 0, max)
    perm := rand.Perm(len(keys))
    for _, i := range perm[:max] {
        peers = append(peers, self[keys[i]])
    }
    return peers
}

// Loads a newline delimited list of addresses from
// "<dir>/<PeerDatabaseFilename>"
func LoadPeerlist(dir string) (Peerlist, error) {
    entries, err := readLines(filepath.Join(dir, PeerDatabaseFilename))
    peerlist := make(Peerlist, len(entries))
    if os.IsNotExist(err) {
        return peerlist, nil
    }
    if err != nil {
        return nil, err
    }
    logInvalid := func(line, msg string) {
        logger.Warning("Invalid peerlist db entry: \"%s\"", line)
        logger.Warning("Reason: %s", msg)
    }
    for _, entry := range entries {
        pts := strings.Split(entry, " ")
        if len(pts) != 2 {
            logInvalid(entry, "Peerlist entry not of form $ADDR $SEEN")
            continue
        }
        addr := pts[0]
        if addr == "" {
            continue
        }
        if !ValidateAddress(addr) {
            logInvalid(addr, fmt.Sprintf("Invalid IP:Port \"%s\"", addr))
            continue
        }
        seen, err := strconv.ParseInt(pts[1], 10, 64)
        if err != nil {
            logInvalid(addr, err.Error())
        }
        peerlist[addr] = &Peer{Addr: addr, LastSeen: time.Unix(seen, 0)}
    }
    return peerlist, nil
}

// Pex manages a set of known peers and controls peer acquisition
type Pex struct {
    // All known peers
    Peerlist Peerlist
    // Ignored peers
    Blacklist Blacklist
    maxPeers  int
}

func NewPex(maxPeers int) *Pex {
    return &Pex{
        Peerlist:  make(Peerlist, maxPeers),
        Blacklist: make(Blacklist, 0),
        maxPeers:  maxPeers,
    }
}

// Adds a peer to the peer list, given an address. If the peer list is
// full, PeerlistFullError is returned */
func (self *Pex) AddPeer(addr string) (*Peer, error) {
    if !ValidateAddress(addr) {
        return nil, InvalidAddressError
    }
    if self.IsBlacklisted(addr) {
        return nil, BlacklistedAddressError
    }
    peer := self.Peerlist[addr]
    if peer != nil {
        peer.Seen()
        return peer, nil
    } else if self.Full() {
        return nil, PeerlistFullError
    } else {
        peer = NewPeer(addr)
        self.Peerlist[peer.Addr] = peer
        return peer, nil
    }
}

// Add a peer address to the blacklist
func (self *Pex) AddBlacklistEntry(addr string, duration time.Duration) {
    if ValidateAddress(addr) {
        delete(self.Peerlist, addr)
        self.Blacklist[addr] = NewBlacklistEntry(duration)
        logger.Debug("Blacklisting peer %s for %s", addr, duration.String())
    } else {
        logger.Warning("Attempted to blacklist invalid IP:Port %s", addr)
    }
}

// Returns whether an address is blacklisted
func (self *Pex) IsBlacklisted(addr string) bool {
    _, is := self.Blacklist[addr]
    return is
}

// Returns true if no more peers can be added
func (self *Pex) Full() bool {
    return self.maxPeers > 0 && len(self.Peerlist) >= self.maxPeers
}

// Sets the maximum number of peers for the list. An existing list will be
// truncated. A maximum of 0 is treated as unlimited
func (self *Pex) SetMaxPeers(max int) {
    if max < 0 {
        log.Panic("Invalid max peers")
    }
    self.maxPeers = max
    if max == 0 {
        return
    }
    peers := make(map[string]*Peer, max)
    ct := 0
    for addr, peer := range self.Peerlist {
        if ct >= max {
            break
        }
        peers[addr] = peer
        ct++
    }
    self.Peerlist = peers
}

// Add multiple peers at once. Any errors will be logged, but not returned
// Returns the number of peers that were added without error.  Note that
// adding a duplicate peer will not cause an error.
func (self *Pex) AddPeers(peers []string) int {
    n := len(peers)
    for _, p := range peers {
        _, err := self.AddPeer(p)
        if err != nil {
            logger.Warning("Failed to add peer %s", p)
            logger.Warning("Reason: %v", err)
            n--
        }
    }
    return n
}

// Loads both the normal peer and blacklisted peer databases
func (self *Pex) Load(dir string) error {
    peerlist, err := LoadPeerlist(dir)
    if err != nil {
        return err
    }
    blacklist, err := LoadBlacklist(dir)
    if err != nil {
        return err
    }
    self.Peerlist = peerlist
    self.Blacklist = blacklist
    // Remove any peers that appear in the blacklist
    for addr, _ := range blacklist {
        delete(self.Peerlist, addr)
    }
    return err
}

// Saves both the normal peer and blacklisted peer databases to dir
func (self *Pex) Save(dir string) error {
    err := self.Peerlist.Save(dir)
    if err == nil {
        err = self.Blacklist.Save(dir)
    }
    return err
}

/* Common utilities */

// Reads a file located at dir/filename and splits it on newlines
func readLines(filename string) ([]string, error) {
    f, err := os.Open(filename)
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
