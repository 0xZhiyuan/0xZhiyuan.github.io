---
pageClass: home-page
# some data for the components

name: Zhiyuan Sun
profile: /profile1.jpg

bio: PhD Student at PolyU & SUSTech
email: zhi-yuan.sun[at]connect.polyu.hk
---

<ProfileSection :frontmatter="$page.frontmatter" />

## Biography

Zhiyuan Sun is a joint Ph.D. student at The Hong Kong Polytechnic University and Southern University of Science and Technology, advised by [Prof. Xiapu Luo](https://www4.comp.polyu.edu.hk/~csxluo/) and [Prof. Yinqian Zhang](https://yinqian.org/). He holds a Bachelor’s degree from Southwest Jiaotong University (2017–2021) and a Master’s degree from King’s College London (2021–2022).

Zhiyuan specializes in blockchain and smart contract security. While he has no interest in playing the academic paper game, he has still authored **two first-author papers** in **top-tier security conferences**, including one that received a **[<span style="color:red;">Distinguished Paper Award</span>](https://www.sigsac.org/ccs/CCS2024/program/awards.html)**, showcasing his ability to deliver impactful research.

Zhiyuan is actually a passionate bug hunter rather than a publication machine, making substantial contributions to Web3 security by uncovering critical vulnerabilities in major projects like Arbitrum and Polygon zkEVM. His efforts have resulted in nearly **40 high-impact vulnerability reports**, preventing billions of dollars in potential losses. These contributions have earned him a total of **[<span style="color:red;">$1.1 million USD in bug bounties</span>](https://immunefi.com/profile/Zhiyuan1999/)**, cementing his position as a respected figure in the blockchain security community. His bug-hunting achievements can be explored on his [Immunefi profile](https://immunefi.com/profile/Zhiyuan1999/).

In addition to his work in blockchain security, Zhiyuan is currently self-studying financial investment and quantitative trading. He is eager to explore collaboration opportunities in these areas. If you are interested in working together, feel free to reach out to him via email.

## Education & Experiences

- **Ph.D Candidate, The Hong Kong Polytechnic University** <br/>
01/2023 - Present

- **Master Degree in King's College London** <br/>
09/2021 - 09/2022

- **Bachelor Degree in Southwest Jiaotong University** <br/>
09/2017 - 06/2021

## Publications
  - **DoubleUp Roll: Double-spending in Arbitrum by Rolling It Back**

    <u>Z. Sun</u>, Z. Li, X. Peng, X. Luo, M. Jiang, H. Zhou, Y. Zhang

    *ACM Conference on Computer and Communications Security (CCS), 2024. [<font color="red">Distinguished Paper Awards</font>](https://www.sigsac.org/ccs/CCS2024/program/awards.html)*

  - **Panda: Security Analysis of Algorand Smart Contracts**

    <u>Z. Sun</u>, X. Luo, Y. Zhang

    *USENIX Security Symposium (USENIX Security 23), 2023.*

  - **Security Threat Mitigation for Smart Contracts: A Comprehensive Survey**

    N. Ivanov, C. Li, Q. Yan, <u>Z. Sun</u>, Z. Cao, X. Luo

    *ACM Computing Surveys, 2023.*





<!-- Custom style for this page -->

<style lang="stylus">

.theme-container.home-page .page
  font-size 14px
  font-family "lucida grande", "lucida sans unicode", lucida, "Helvetica Neue", Helvetica, Arial, sans-serif;
  p
    margin 0 0 0.5rem
  p, ul, ol
    line-height normal
  a
    font-weight normal
  .theme-default-content:not(.custom) > h2
    margin-bottom 0.5rem
  .theme-default-content:not(.custom) > h2:first-child + p
    margin-top 0.5rem
  .theme-default-content:not(.custom) > h3
    padding-top 4rem

  /* Override */
  .md-card
    margin-top 0.5em
    .card-image
      padding 0.2rem
      img
        max-width 120px
        max-height 120px
    .card-content p
      -webkit-margin-after 0.2em

@media (max-width: 419px)
  .theme-container.home-page .page
    p, ul, ol
      line-height 1.5

    .md-card
      .card-image
        img 
          width 100%
          max-width 400px

</style>
