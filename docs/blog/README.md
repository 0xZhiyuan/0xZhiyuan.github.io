---
pageClass: projects-page
---

# Blog

**I will share all my bug hunting findings here, this blog will be updated gradually. Enjoy reading!**

<ProjectCard>
  
  **Polygon zkEVM Series 1: Dual Execution Path Vulnerabilities**

  To be writing....

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