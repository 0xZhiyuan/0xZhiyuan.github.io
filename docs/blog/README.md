---
pageClass: projects-page
---

# Blog

**I will share all my bug hunting findings here, this blog will be updated gradually. Enjoy reading!**

<ProjectCard>
  
  **Polygon zkEVM Series 5: Denial of Service against Sequencer**

  To be writting...

</ProjectCard>

<ProjectCard>
  
  **Polygon zkEVM Series 4: Under-Constrained Sparse Merkle Tree**

  To be writting...

</ProjectCard>

<ProjectCard>
  
  **Polygon zkEVM Series 3: ROM-Induced Unprovable Transactions**

  <span style="color:green;">Label:</span> <span style="color:red;">ZK-Related Bug</span>

  The ROM-induced unprovable transaction vulnerability in zk systems occurs when the ROM lacks checks for zkCounter or an execution path in the ROM contains unsolvable constraints. This blog discuss 4 ROM-induced unprovable transaction vulnerabilities.

  [[Click here to see details](./5)]

</ProjectCard>

<ProjectCard>
  
  **Polygon zkEVM Series 2: Executor-Induced Unprovable Transactions**

  <span style="color:green;">Label:</span> <span style="color:red;">ZK-Related Bug, Critical Impact, Complex Bug</span>

  The executor-induced unprovable transaction vulnerability in zk systems occurs when the state transition produced by the executor (witness calculator) fails to satisfy the constraint system. This is usually caused by a computational error in the executor.

  [[Click here to see details](./4)]

</ProjectCard>

<ProjectCard>
  
  **Polygon zkEVM Series 1: Dual Execution Paths**

  <span style="color:green;">Label:</span> <span style="color:red;">ZK-Related Bug, Complex Bug</span>

  A dual execution path vulnerability is fundamentally a soundness vulnerability. In the context of a zkEVM written in zkasm, such a vulnerability arises when multiple execution paths can lead to the same final state but consume different zk-related resources (e.g., STEP counters). This blog discuss 3 dual execution path vulnerabilities.

  [[Click here to see details](./3)]

</ProjectCard>

<ProjectCard>
  
  **Misconfiguration of Ethereum RPC Series 2: Unlimited Batch Requests**

  <span style="color:green;">Label:</span> <span style="color:red;">Multiple Venders Affected</span>

  Ethereum-based L2 implementations lack limits on batch request size or number, making nodes vulnerable to memory exhaustion and crashes. Several leading projects, such as Polygon zkEVM and Scroll, are affected by this vulnerability.

  [[Click here to see details](./2)]

</ProjectCard>

<ProjectCard>
  
  **Misconfiguration of Ethereum RPC Series 1: RPC Debug Mode Enabled**

  <span style="color:green;">Label:</span> <span style="color:red;">Multiple Venders Affected</span>

  Ethereum nodes with RPC debug mode enabled in production are vulnerable to attacks, leading to node crashes and data corruption. Several leading projects, such as Arbitrum and Boba network, are affected by this vulnerability.

  [[Click here to see details](./1)]

</ProjectCard>

<ProjectCard>
  
  **Double-Spending Vulnerabilities on Arbitrum**

  <span style="color:green;">Label:</span> <span style="color:red;">Critical Impact, Complex Bug</span>

  In 2022, I started to study the Arbitrum codebase and found several critical double-spending vulnerabilities. These double-spending vulnerabilities could cause billions of dollars in direct losses to third-party cross-chain bridges and centralized exchanges. Arbiturm fixed these vulnerabilities in a timely manner and gave me huge bug bounties.
  
  [[Research Paper PDF](../files/DoubleUp_Roll__Final_Version_.pdf)]

</ProjectCard>


<ProjectCard>

  **Security Analysis of Algorand Smart Contracts**

  While reviewing the Algorand ecosystem, I identified several generic vulnerabilities within Algorand smart contracts, stemming from incorrect programming practices. I developed a static analysis tool to automatically find these bugs, and conducted a comprehensive vulnerability scan of Algorand’s blockchain. Many projects, including key blockchain platforms like decentralized exchanges and NFT auction systems, have acknowledged the vulnerabilities found by my tool. I also received bug bounties from some projects.

  [[Research Paper PDF](../files/Panda__Security_Analysis_of_Algorand_Smart_Contracts.pdf)]

</ProjectCard>

<style lang="stylus">

.projects-page
  background-color #fafbfc

</style>