#Our minitnet
import pdb
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange, dumpNodeConnections
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        #Add 6 host vo
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")
        h5 = self.addHost("h5")
        h6 = self.addHost("h6")

        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        SwitchList = (s1,s2,s3)

        self.addLink(h1,s1)
        self.addLink(h2,s1)
        self.addLink(h3,s1)
        self.addLink(h4,s2)
        self.addLink(h5,s2)
        self.addLink(h6,s3)
topos = { 'mytopo': ( lambda: myTopo() ) }


