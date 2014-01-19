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
    "strings"
    "testing"
    "time"
)

var (
    address   = "112.32.32.14:3030"
    addresses = []string{
        address, "111.32.32.13:2020", "69.32.54.111:2222",
    }
)

func init() {
    // silence the logger
    logging.SetBackend(logging.NewLogBackend(ioutil.Discard, "", 0))
}

func TestValidateAddress(t *testing.T) {
    // empty string
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
    // Create and save a blacklist
    os.Remove("./" + BlacklistedDatabaseFilename)
    b := make(Blacklist)
    be := NewBlacklistEntry(time.Minute)
    b[address] = be
    b[""] = be
    b.Save(".")

    // Check that the file appears correct
    f, err := os.Open("./" + BlacklistedDatabaseFilename)
    assert.Nil(t, err)
    buf := make([]byte, 1024)
    reader := bufio.NewReader(f)
    n, err := reader.Read(buf)
    assert.Nil(t, err)
    buf = buf[:n]
    assert.Equal(t, string(buf[:len(address)]), address)
    assert.Equal(t, int8(buf[len(buf)-1]), '\n')
    f.Close()

    // Load the saved blacklist, check the contents match
    bb, err := LoadBlacklist(".")
    assert.Nil(t, err)
    assert.Equal(t, len(bb), len(b)-1)
    for k, v := range bb {
        assert.Equal(t, v.Start.Unix(), b[k].Start.Unix())
        assert.Equal(t, v.Duration, b[k].Duration)
    }

    // Write a file with bad data
    f, err = os.Create("./" + BlacklistedDatabaseFilename)
    assert.Nil(t, err)
    garbage := []string{
        "", // empty line
        "#" + address + " 1000 1000", // commented line
        "notaddress 1000 1000",       // bad address
        address + " xxx 1000",        // bad start time
        address + " 1000 xxx",        // bad duration
        address + " 1000",            // not enough info
        // this one is good, but has extra spaces
        address + "  9999999999\t\t1000",
    }
    w := bufio.NewWriter(f)
    data := strings.Join(garbage, "\n") + "\n"
    n, err = w.Write([]byte(data))
    assert.Nil(t, err)
    w.Flush()
    f.Close()

    // Load the file with bad data and confirm they did not make it
    bb, err = LoadBlacklist(".")
    assert.Nil(t, err)
    assert.Equal(t, len(bb), 1)
    assert.NotNil(t, bb[address])
    assert.Equal(t, bb[address].Duration, time.Duration(1000)*time.Second)
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

func TestBlacklistGetAddresses(t *testing.T) {
    b := make(Blacklist)
    for _, a := range addresses {
        b[a] = NewBlacklistEntry(time.Second)
    }
    expect := make([]string, len(addresses))
    for i, k := range addresses {
        expect[i] = k
    }
    sort.Strings(expect)
    keys := b.GetAddresses()
    sort.Strings(keys)
    assert.Equal(t, len(keys), len(expect))
    for i, v := range keys {
        assert.Equal(t, v, expect[i])
    }

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
    // blacklisting invalid peer triggers logger -- just get the coverage
    p.AddBlacklistEntry("xxx", time.Second)
    _, exists = p.Blacklist["xxx"]
    assert.Equal(t, exists, false)
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

func TestAddPeers(t *testing.T) {
    p := NewPex(10)
    peers := make([]string, 3)
    peers[0] = "112.32.32.14:10011"
    peers[1] = "112.32.32.14:20011"
    peers[2] = "xxx"
    n := p.AddPeers(peers)
    assert.Equal(t, n, 2)
    assert.NotNil(t, p.Peerlist[peers[0]])
    assert.NotNil(t, p.Peerlist[peers[1]])
    assert.Nil(t, p.Peerlist[peers[2]])
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

    // Adding blacklisted peer is invalid
    delete(p.Peerlist, address)
    p.AddBlacklistEntry(address, time.Second)
    peer, err = p.AddPeer(address)
    assert.NotNil(t, err)
    assert.Nil(t, peer)
    assert.Nil(t, p.Peerlist[address])
}

func TestSaveLoad(t *testing.T) {
    p := NewPex(10)
    p.AddPeer("112.32.32.14:10011")
    p.AddPeer("112.32.32.14:20011")
    // bypass AddPeer to add a blacklist and normal address at the same time
    // saving this and reloading it should cause the address to be
    // blacklisted only
    bad := "111.44.44.22:11021"
    p.Peerlist[bad] = NewPeer(bad)
    p.AddBlacklistEntry(bad, time.Hour)
    err := p.Save("./")
    assert.Nil(t, err)

    q := NewPex(10)
    err = q.Load("./")
    assert.Nil(t, err)
    assert.NotNil(t, q.Peerlist["112.32.32.14:10011"])
    assert.NotNil(t, q.Peerlist["112.32.32.14:20011"])
    assert.Nil(t, q.Peerlist[bad])
    _, exists := q.Blacklist[bad]
    assert.Equal(t, exists, true)

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
