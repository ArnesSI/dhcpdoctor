DEBUG = False
"""bool: Debugging mode"""

IFACE = None
"""str: Send requests out of this interface.

Should be a string matching interface name. If not set, conf.iface from scapy is used.
"""

PROTOCOL = 4
"""int: DHCP protocol to operate in.

4 for DHCPv4, 6 for DHCPv6
"""

RELAY_MODE = False
"""bool: Send requests with relay information set or broadcast to local netowrk.

True for relay, False for broadcast
"""

SERVER_ADDRESS = None
"""str: IP address of DHCP server to send request to if using `RELAY_MODE`."""

RELAY_ADDRESS = None
"""str: IP address to send requests from if using `RELAY_MODE`."""

TIMEOUT = 5
"""int: seconds to wait for a reply from server"""