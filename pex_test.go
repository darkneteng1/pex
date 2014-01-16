package pex

import (
    "bufio"
    "fmt"
    "github.com/op/go-logging"
    "github.com/stretchr/testify/assert"
    "io/ioutil"
    "net"
    "os"
    "sort"
    "testing"
    "time"
)

var address string = "112.32.32.14:3030"

func init() {
    // silence the logger
    logging.SetBackend(logging.NewLogBackend(ioutil.Discard, "", 0))
}

// empty string
func TestValidateAddress(t *testing.T) {
    assert.Equal(t, ValidateAddress(""), false)
    // doubled ip:port
    assert.Equal(t, ValidateAddress("112.32.32.14:100112.32.32.14:101"), false)
    // requires port
    assert.Equal(t, ValidateAddress("112.32.32.14"), false)
    // not ip
    assert.Equal(t, ValidateAddress("112"), false)
    assert.Equal(t, ValidateAddress("112.32"), false)
    assert.Equal(t, ValidateAddress("112.32.32"), false)
    // bad part
    assert.Equal(t, ValidateAddress("112.32.32.14000"), false)
    // large port
    assert.Equal(t, ValidateAddress("112.32.32.14:66666"), false)
    // localhost
    assert.Equal(t, ValidateAddress("127.0.0.1:8888"), false)
    // unspecified
    assert.Equal(t, ValidateAddress("0.0.0.0:8888"), false)
    // no ip
    assert.Equal(t, ValidateAddress(":8888"), false)
    // multicast
    assert.Equal(t, ValidateAddress("224.1.1.1:8888"), false)
    // invalid ports
    assert.Equal(t, ValidateAddress("112.32.32.14:0"), false)
    assert.Equal(t, ValidateAddress("112.32.32.14:1"), false)
    assert.Equal(t, ValidateAddress("112.32.32.14:10"), false)
    assert.Equal(t, ValidateAddress("112.32.32.14:100"), false)
    assert.Equal(t, ValidateAddress("112.32.32.14:1000"), false)
    assert.Equal(t, ValidateAddress("112.32.32.14:1023"), false)
    assert.Equal(t, ValidateAddress("112.32.32.14:65536"), false)
    // valid ones
    assert.Equal(t, ValidateAddress("112.32.32.14:1024"), true)
    assert.Equal(t, ValidateAddress("112.32.32.14:10000"), true)
    assert.Equal(t, ValidateAddress("112.32.32.14:65535"), true)
}

/* Peer tests */

func TestNewPeer(t *testing.T) {
    p := NewPeer(address)
    assert.NotEqual(t, p.LastSeen, 0)
    assert.Equal(t, p.Addr, address)
}

func TestPeerSeen(t *testing.T) {
    p := NewPeer(address)
    x := p.LastSeen
    time.Sleep(time.Second)
    p.Seen()
    assert.NotEqual(t, x, p.LastSeen)
    if p.LastSeen <= x {
        t.Fail()
    }
}

func TestPeerString(t *testing.T) {
    p := NewPeer(address)
    assert.Equal(t, address, p.String())
}

/* BlacklistEntry tests */

func TestBlacklistEntryExpiresAt(t *testing.T) {
    now := time.Now().UTC()
    b := BlacklistEntry{Start: now, Duration: time.Second}
    assert.Equal(t, now.Add(time.Second), b.ExpiresAt())
}

/* Blacklist tests */

func TestBlacklistSaveLoad(t *testing.T) {
    os.Remove("./" + BlacklistedDatabaseFilename)
    b := make(Blacklist)
    be := NewBlacklistEntry(time.Minute)
    b[address] = be
    b[""] = be
    b.Save(".")

    f, err := os.Open("./" + BlacklistedDatabaseFilename)
    assert.Nil(t, err)
    buf := make([]byte, 1024)
    reader := bufio.NewReader(f)
    n, err := reader.Read(buf)
    assert.Nil(t, err)
    buf = buf[:n]
    t.Log(string(buf))
    assert.Equal(t, string(buf[:len(address)]), address)
    assert.Equal(t, int8(buf[len(buf)-1]), '\n')
    f.Close()

    bb, err := LoadBlacklist(".")
    assert.Nil(t, err)
    assert.Equal(t, len(bb), len(b)-1)
    for k, v := range bb {
        assert.Equal(t, v.Start.Unix(), b[k].Start.Unix())
        assert.Equal(t, v.Duration, b[k].Duration)
    }
}

func TestBlacklistRefresh(t *testing.T) {
    b := make(Blacklist)
    be := NewBlacklistEntry(time.Microsecond)
    b[address] = be
    time.Sleep(time.Microsecond * 500)
    assert.Equal(t, len(b), 1)
    b.Refresh()
    assert.Equal(t, len(b), 0)
}

/* Pex tests */

func TestNewPex(t *testing.T) {
    p := NewPex(10)
    assert.NotNil(t, p.Peerlist)
    assert.Equal(t, len(p.Peerlist), 0)
    assert.NotNil(t, p.Blacklist)
    assert.Equal(t, p.maxPeers, 10)
}

func TestAddBlacklistEntry(t *testing.T) {
    p := NewPex(10)
    p.AddPeer(address)
    assert.NotNil(t, p.Peerlist[address])
    _, exists := p.Blacklist[address]
    assert.Equal(t, exists, false)
    duration := time.Minute * 9
    p.AddBlacklistEntry(p.Peerlist[address].Addr, duration)
    assert.Nil(t, p.Peerlist[address])
    assert.Equal(t, p.Blacklist[address].Duration, duration)
    now := time.Now()
    assert.Equal(t, p.Blacklist[address].Start.Before(now), true)
    assert.Equal(t, p.Blacklist[address].Start.Add(duration).After(now),
        true)
}

func TestSetMaxPeers(t *testing.T) {
    p := NewPex(10)
    p.SetMaxPeers(20)
    assert.Equal(t, p.maxPeers, 20)

    // test truncating the peers map
    for i := 0; i < 20; i++ {
        p.AddPeer(fmt.Sprintf("112.32.32.14:%d", i+6000))
    }
    assert.Equal(t, len(p.Peerlist), 20)
    p.SetMaxPeers(10)
    assert.Equal(t, len(p.Peerlist), 10)

    // setting invalid raises panic
    defer func() {
        if r := recover(); r == nil {
            // we should have caught a panic
            assert.NotNil(t, nil)
        }
    }()
    p.SetMaxPeers(-1)
}

func TestRequestPeers(t *testing.T) {
    dummyGetSent = false
    connections := make([]net.Conn, 2)
    connections[0] = &DummyConnection{}
    connections[1] = &DummyConnection{}
    p := NewPex(1)
    p.RequestPeers(connections, NewDummyGetPeersMessage)
    assert.Equal(t, dummyGetSent, true)
    dummyGetSent = false

    // Test with Full()
    p.AddPeer("112.32.32.14:10011")
    p.RequestPeers(connections, NewDummyGetPeersMessage)
    assert.Equal(t, dummyGetSent, false)
    dummyGetSent = false
}

func TestRespondToGivePeersMessage(t *testing.T) {
    p := NewPex(10)
    peers := make([]*Peer, 2)
    peers[0] = NewPeer("112.32.32.14:10011")
    peers[1] = NewPeer("112.32.32.14:20011")
    m := NewDummyGivePeersMessage(peers)
    p.RespondToGivePeersMessage(m)
    assert.NotNil(t, p.Peerlist[peers[0].String()])
    assert.NotNil(t, p.Peerlist[peers[1].String()])
}

func TestResponseToGetPeersMessage(t *testing.T) {
    dummyGiveSent = false
    p := NewPex(10)
    c := &DummyConnection{}

    // check without peers
    _m := p.RespondToGetPeersMessage(c, NewDummyGivePeersMessage)
    assert.Nil(t, _m)

    // check with peers
    p.AddPeer("112.32.32.14:10011")
    p.AddPeer("112.32.32.14:20011")
    _m = p.RespondToGetPeersMessage(c, NewDummyGivePeersMessage)
    m, ok := _m.(*DummyGivePeersMessage)
    assert.Equal(t, ok, true)
    assert.Equal(t, len(m.peers), 2)
    for _, peer := range m.peers {
        assert.Equal(t, (peer.String() == "112.32.32.14:10011" ||
            peer.String() == "112.32.32.14:20011"), true)
    }
    assert.Equal(t, dummyGiveSent, true)
    dummyGiveSent = false
}

func TestClearOld(t *testing.T) {
    p := NewPex(10)
    p.AddPeer("112.32.32.14:10011")
    p.AddPeer("112.32.32.14:20011")
    assert.Equal(t, len(p.Peerlist), 2)
    p.Peerlist.ClearOld(100)
    assert.Equal(t, len(p.Peerlist), 2)
    p.Peerlist["112.32.32.14:20011"].LastSeen -= 101
    p.Peerlist.ClearOld(100)
    assert.Equal(t, len(p.Peerlist), 1)
    assert.Nil(t, p.Peerlist["112.32.32.14:20011"])
    assert.NotNil(t, p.Peerlist["112.32.32.14:10011"])
}

func TestGetAddresses(t *testing.T) {
    p := NewPex(10)
    p.AddPeer("112.32.32.14:10011")
    p.AddPeer("112.32.32.14:20011")
    addresses := p.Peerlist.GetAddresses()
    assert.Equal(t, len(addresses), 2)
    sort.Strings(addresses)
    assert.Equal(t, addresses, []string{
        "112.32.32.14:10011",
        "112.32.32.14:20011",
    })
}

func convertPeersToStrings(peers []*Peer) []string {
    addresses := make([]string, 0, len(peers))
    for _, p := range peers {
        addresses = append(addresses, p.String())
    }
    return addresses
}

func compareRandomPeers(t *testing.T, p *Pex, npeers int,
    result []string) {
    peers := p.Peerlist.Random(npeers)
    addresses := convertPeersToStrings(peers)
    sort.Strings(addresses)
    assert.Equal(t, addresses, result)
}

func TestRandomPeers(t *testing.T) {
    p := NewPex(10)
    // check without peers
    assert.NotNil(t, p.Peerlist.Random(100))
    assert.Equal(t, len(p.Peerlist.Random(100)), 0)

    // check with one peer
    p.AddPeer("112.32.32.14:10011")
    // 0 defaults to all peers
    compareRandomPeers(t, p, 0, []string{"112.32.32.14:10011"})
    compareRandomPeers(t, p, 1, []string{"112.32.32.14:10011"})
    // exceeding known peers is safe
    compareRandomPeers(t, p, 2, []string{"112.32.32.14:10011"})
    // exceeding max peers is safe
    compareRandomPeers(t, p, 100, []string{"112.32.32.14:10011"})

    // check with two peers
    p.AddPeer("112.32.32.14:20011")
    // 0 defaults to all peers
    one := p.Peerlist.Random(1)[0].String()
    if one != "112.32.32.14:10011" && one != "112.32.32.14:20011" {
        assert.Nil(t, nil)
    }
    compareRandomPeers(t, p, 0, []string{
        "112.32.32.14:10011",
        "112.32.32.14:20011",
    })
    compareRandomPeers(t, p, 2, []string{
        "112.32.32.14:10011",
        "112.32.32.14:20011",
    })
    compareRandomPeers(t, p, 3, []string{
        "112.32.32.14:10011",
        "112.32.32.14:20011",
    })
    compareRandomPeers(t, p, 100, []string{
        "112.32.32.14:10011",
        "112.32.32.14:20011",
    })
}

func TestGetPeer(t *testing.T) {
    p := NewPex(10)
    p.AddPeer("112.32.32.14:10011")
    assert.Nil(t, p.Peerlist["xxx"])
    assert.Equal(t, p.Peerlist["112.32.32.14:10011"].String(),
        "112.32.32.14:10011")
}

func TestFull(t *testing.T) {
    p := NewPex(1)
    assert.Equal(t, p.Full(), false)
    p.AddPeer("112.32.32.14:10011")
    assert.Equal(t, p.Full(), true)
    p.SetMaxPeers(0)
    assert.Equal(t, p.Full(), false)
}

func TestAddPeer(t *testing.T) {
    p := NewPex(1)

    // adding "" peer results in error
    peer, err := p.AddPeer("")
    assert.Nil(t, peer)
    assert.NotNil(t, err)
    assert.Equal(t, err, InvalidAddressError)
    assert.Equal(t, len(p.Peerlist), 0)

    peer, err = p.AddPeer("112.32.32.14:10011")
    assert.Nil(t, err)
    assert.Equal(t, peer.String(), "112.32.32.14:10011")
    assert.NotNil(t, p.Peerlist["112.32.32.14:10011"])
    past := peer.LastSeen

    // full list
    twopeer, err := p.AddPeer("112.32.32.14:20011")
    assert.Equal(t, err, PeerlistFullError)
    assert.Nil(t, twopeer)
    assert.Nil(t, p.Peerlist["112.32.32.14:20011"])

    // re-add original peer
    time.Sleep(time.Second)
    repeer, err := p.AddPeer("112.32.32.14:10011")
    assert.Nil(t, err)
    assert.NotNil(t, repeer)
    assert.Equal(t, peer, repeer)
    assert.Equal(t, repeer.String(), "112.32.32.14:10011")
    assert.Equal(t, repeer.LastSeen > past, true)

    assert.NotNil(t, p.Peerlist["112.32.32.14:10011"])
}

func TestSaveLoad(t *testing.T) {
    p := NewPex(10)
    p.AddPeer("112.32.32.14:10011")
    p.AddPeer("112.32.32.14:20011")
    err := p.Save("./")
    assert.Nil(t, err)

    q := NewPex(10)
    err = q.Load("./")
    assert.Nil(t, err)
    assert.NotNil(t, q.Peerlist["112.32.32.14:10011"])
    assert.NotNil(t, q.Peerlist["112.32.32.14:20011"])

    // TODO -- any way to force os.Create or f.WriteString to return an error?
}

/* Addendum: dummies & mocks */

// Fake addr that satisfies net.Addr interface
type DummyAddr struct{}

func (self *DummyAddr) Network() string {
    return self.String()
}

func (self *DummyAddr) String() string {
    return "none"
}

// Fake connection that satisfies net.Conn interface
type DummyConnection struct{}

func (self *DummyConnection) Read(b []byte) (int, error) {
    return 0, nil
}

func (self *DummyConnection) Write(b []byte) (int, error) {
    return 0, nil
}

func (self *DummyConnection) Close() error {
    return nil
}

func (self *DummyConnection) LocalAddr() net.Addr {
    return &DummyAddr{}
}

func (self *DummyConnection) RemoteAddr() net.Addr {
    return &DummyAddr{}
}

func (self *DummyConnection) SetDeadline(t time.Time) error {
    return nil
}

func (self *DummyConnection) SetReadDeadline(t time.Time) error {
    return nil
}

func (self *DummyConnection) SetWriteDeadline(t time.Time) error {
    return nil
}

// Satisfies GetPeersMessage interface
type DummyGetPeersMessage struct{}

var dummyGetSent bool = false

func (self *DummyGetPeersMessage) Send(c net.Conn) error {
    dummyGetSent = true
    return nil
}

func NewDummyGetPeersMessage() GetPeersMessage {
    return &DummyGetPeersMessage{}
}

// Satisfies GivePeersMessage interface
type DummyGivePeersMessage struct {
    peers []*Peer
}

var dummyGiveSent bool = false

func (self *DummyGivePeersMessage) Send(c net.Conn) error {
    dummyGiveSent = true
    return nil
}

func (self *DummyGivePeersMessage) GetPeers() []string {
    p := make([]string, len(self.peers))
    for i, peer := range self.peers {
        p[i] = peer.String()
    }
    return p
}

func NewDummyGivePeersMessage(p []*Peer) GivePeersMessage {
    return &DummyGivePeersMessage{peers: p}
}
