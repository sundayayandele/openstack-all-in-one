# BlueHarvest AI Model Use Case Guide
**Private Cloud Intelligence Platform**

*Prepared by Private Cloud | February 2026*

---

## Introduction

The BlueHarvest AI platform provides access to eight carefully selected open-source large language models, each optimized for specific use cases. This guide helps administrators and users select the right model for each task, maximizing quality and efficiency across the platform.

All models run locally on the BlueHarvest AI infrastructure via Ollama, ensuring complete data privacy and zero dependence on external API services. Models are accessible through the web interface at **lls.blueharvestai.com**, authenticated via OpenStack.

---

## Quick Reference Table

| Model | Parameters | Quantization | RAM | Speed | Primary Use Case |
|-------|-----------|--------------|-----|-------|------------------|
| **Mistral 7B** | 7.2B | Q4_K_M | ~4.5 GB | Fast | Quick general-purpose Q&A and conversational AI |
| **LLaMA 2 13B** | 13B | Q4_0 | ~7.4 GB | Moderate | Detailed content writing and long-form text generation |
| **DeepSeek-R1 (8B)** | 8.2B | Q4_K_M | ~5.2 GB | Moderate | Mathematical problem-solving and numerical analysis |
| **Mixtral 8x7B** | 46.7B | Q4_0 | ~26 GB | Slower | Complex multi-domain tasks requiring broad expertise |
| **Qwen 2.5 14B** | 14.8B | Q4_K_M | ~9 GB | Moderate | Multilingual tasks, especially English-Chinese translation |
| **Gemma 2 9B** | 9.2B | Q4_0 | ~5.5 GB | Fast | Safe, well-aligned conversational AI for customer-facing |
| **Phi-3 14B** | 14B | Q4_0 | ~7.9 GB | Moderate | Research assistance and academic writing support |
| **Code Llama 13B** | 13B | Q4_0 | ~7.4 GB | Moderate | Code generation across Python, JavaScript, Java, C++ |

---

## Detailed Model Profiles

### 1. Mistral 7B

| Specification | Value |
|--------------|-------|
| **Parameters** | 7.2B |
| **Quantization** | Q4_K_M |
| **Estimated RAM** | ~4.5 GB |
| **Inference Speed** | Fast |

#### Overview
A compact, high-efficiency general-purpose model that punches well above its weight class. Mistral 7B outperforms models twice its size on reasoning, mathematics, and code generation benchmarks thanks to innovations like Grouped-Query Attention and Sliding Window Attention.

#### Best Use Cases
- Quick general-purpose Q&A and conversational AI
- Text summarization, classification, and sentiment analysis
- Lightweight chatbot deployments where speed matters
- Content moderation and text filtering
- Real-time applications requiring low-latency responses
- Default model for everyday tasks on resource-constrained hardware

#### Not Ideal For
Complex multi-step reasoning, very large document analysis, or tasks requiring deep domain expertise.

#### BlueHarvest AI Recommendation
Use Mistral as your **default daily driver model**. It offers the best balance of speed and quality for routine tasks, making it ideal as the primary model for most BlueHarvest AI users.

---

### 2. LLaMA 2 13B

| Specification | Value |
|--------------|-------|
| **Parameters** | 13B |
| **Quantization** | Q4_0 |
| **Estimated RAM** | ~7.4 GB |
| **Inference Speed** | Moderate |

#### Overview
Meta's foundational open-source model with 13 billion parameters. LLaMA 2 13B provides a meaningful step up in knowledge depth and contextual understanding compared to 7B models, while remaining manageable in terms of resource consumption.

#### Best Use Cases
- Detailed content writing and long-form text generation
- Knowledge-intensive Q&A requiring broader world knowledge
- Document drafting including reports, emails, and proposals
- Multi-turn conversations requiring consistent context retention
- Educational content creation and tutoring assistance
- General research assistance and information synthesis

#### Not Ideal For
Highly specialized coding tasks, advanced mathematical reasoning, or tasks where the latest training data is critical.

#### BlueHarvest AI Recommendation
Choose LLaMA 2 13B when you need more depth than Mistral can provide, particularly for content writing and knowledge-heavy conversations. It is a **solid middle-ground model**.

---

### 3. DeepSeek-R1 (8B Distilled)

| Specification | Value |
|--------------|-------|
| **Parameters** | 8.2B |
| **Quantization** | Q4_K_M |
| **Estimated RAM** | ~5.2 GB |
| **Inference Speed** | Moderate |

#### Overview
A distilled reasoning model that inherits chain-of-thought capabilities from the full DeepSeek-R1 671B model. This compact version excels at step-by-step logical reasoning, mathematical problem-solving, and structured analytical thinking, achieving 89.1% on the MATH-500 benchmark.

#### Best Use Cases
- Mathematical problem-solving and numerical analysis
- Step-by-step logical reasoning and chain-of-thought tasks
- Scientific and technical question answering
- Debugging code through logical analysis
- Financial calculations and data interpretation
- Exam preparation and academic problem-solving

#### Not Ideal For
Creative writing, casual conversation, or tasks where reasoning overhead is unnecessary.

#### BlueHarvest AI Recommendation
Use DeepSeek-R1 whenever you face problems that require **structured thinking, mathematical reasoning, or step-by-step analysis**. It is the go-to model for analytical and STEM-related queries on the BlueHarvest AI platform.

---

### 4. Mixtral 8x7B (MoE)

| Specification | Value |
|--------------|-------|
| **Parameters** | 46.7B |
| **Quantization** | Q4_0 |
| **Estimated RAM** | ~26 GB |
| **Inference Speed** | Slower |

#### Overview
Mixtral is a Mixture of Experts (MoE) model with 46.7 billion total parameters but only activates approximately 12.9 billion per inference pass. This architecture delivers near-frontier performance across multiple domains while maintaining reasonable inference speed. It supports a 32K token context window.

#### Best Use Cases
- Complex multi-domain tasks requiring broad expertise
- Long document analysis and summarization (up to 32K tokens)
- Advanced code generation across multiple programming languages
- Multilingual tasks including translation and cross-lingual QA
- Enterprise-grade content creation and technical writing
- Tasks requiring the highest quality output from local models

#### Not Ideal For
Quick, simple queries where speed matters more than depth, or environments with less than 28 GB of available RAM.

#### BlueHarvest AI Recommendation
Mixtral is the **premium model** on the platform. Deploy it for your most demanding tasks where output quality is paramount, such as enterprise document analysis, complex code generation, or when serving advanced users who need frontier-level local AI.

---

### 5. Qwen 2.5 14B

| Specification | Value |
|--------------|-------|
| **Parameters** | 14.8B |
| **Quantization** | Q4_K_M |
| **Estimated RAM** | ~9 GB |
| **Inference Speed** | Moderate |

#### Overview
Developed by Alibaba Cloud, Qwen 2.5 14B is a strong multilingual model with excellent performance in both English and Chinese, as well as broad support for other languages. It excels in structured data tasks, tool usage, and instruction following, with robust coding capabilities.

#### Best Use Cases
- Multilingual tasks, especially English-Chinese translation and QA
- Structured output generation (JSON, tables, formatted data)
- Tool use and function calling in agentic workflows
- Business analytics and structured data interpretation
- Cross-cultural content adaptation for African and Asian markets
- API integration tasks requiring precise instruction following

#### Not Ideal For
Tasks exclusively in English where a smaller model would suffice, or pure creative writing tasks.

#### BlueHarvest AI Recommendation
Qwen 2.5 14B is ideal for **business automation, structured data tasks, and multilingual deployments**. For Private Cloud clients working with diverse language requirements or needing AI-powered data processing pipelines, this model delivers excellent value.

---

### 6. Gemma 2 9B

| Specification | Value |
|--------------|-------|
| **Parameters** | 9.2B |
| **Quantization** | Q4_0 |
| **Estimated RAM** | ~5.5 GB |
| **Inference Speed** | Fast |

#### Overview
Google DeepMind's Gemma 2 9B is an efficient, well-rounded model that excels at instruction following and safety alignment. Built with Google's responsible AI practices, it provides reliable, well-calibrated responses with strong factual accuracy for its size class.

#### Best Use Cases
- Safe, well-aligned conversational AI for customer-facing deployments
- Factual question answering with reliable, calibrated responses
- Educational and training applications requiring accuracy
- Content generation with strong safety guardrails
- Summarization and information extraction from documents
- Production deployments where response reliability is critical

#### Not Ideal For
Highly creative or unconstrained text generation, or tasks requiring expertise beyond its training scope.

#### BlueHarvest AI Recommendation
Deploy Gemma 2 for **customer-facing applications and educational platforms** where safety, accuracy, and reliability are non-negotiable. It is particularly well-suited for Private Cloud's LMS and training applications.

---

### 7. Phi-3 14B

| Specification | Value |
|--------------|-------|
| **Parameters** | 14B |
| **Quantization** | Q4_0 |
| **Estimated RAM** | ~7.9 GB |
| **Inference Speed** | Moderate |

#### Overview
Microsoft's Phi-3 14B is a research-optimized model that achieves remarkable performance through high-quality training data curation rather than sheer scale. It demonstrates strong reasoning, common sense understanding, and coding ability, often matching models two to three times its size.

#### Best Use Cases
- Research assistance and academic writing support
- Code generation and software development tasks
- Reasoning-intensive tasks with strong common sense requirements
- Data analysis and interpretation
- Technical documentation and specification writing
- Prototyping and rapid development workflows

#### Not Ideal For
Very long context tasks, heavy multilingual workloads, or highly creative storytelling.

#### BlueHarvest AI Recommendation
Phi-3 is excellent for **development teams and technical staff**. Use it for code generation, technical documentation, and research tasks where Microsoft's training data quality translates into precise, well-structured outputs.

---

### 8. Code Llama 13B

| Specification | Value |
|--------------|-------|
| **Parameters** | 13B |
| **Quantization** | Q4_0 |
| **Estimated RAM** | ~7.4 GB |
| **Inference Speed** | Moderate |

#### Overview
Meta's specialized code-focused model built on the LLaMA 2 architecture with additional training on code-specific datasets. Code Llama 13B supports fill-in-the-middle completions, long code context understanding, and generation across dozens of programming languages.

#### Best Use Cases
- Code generation across Python, JavaScript, Java, C++, and more
- Code completion and fill-in-the-middle suggestions
- Code review, refactoring, and optimization
- Debugging assistance and error explanation
- Writing unit tests and documentation from code
- DevOps scripting (Bash, Ansible, Terraform, Docker)

#### Not Ideal For
General conversation, creative writing, knowledge-based Q&A, or non-programming tasks.

#### BlueHarvest AI Recommendation
Code Llama is the **dedicated coding assistant** on the platform. Use it exclusively for software development tasks. For Private Cloud's DevOps automation, infrastructure scripting, and internal tool development, this model will deliver the most precise and contextually aware code output.

---

## Model Selection Decision Guide

Use this quick-reference guide to select the optimal model based on your task type:

| Task Type | Recommended Model | Alternative |
|-----------|------------------|-------------|
| **Quick Q&A / Chat** | Mistral 7B | Gemma 2 9B |
| **Content Writing** | LLaMA 2 13B | Mixtral |
| **Math / Reasoning** | DeepSeek-R1 | Phi-3 14B |
| **Code Generation** | Code Llama 13B | Phi-3 14B |
| **Long Documents** | Mixtral | Qwen 2.5 14B |
| **Multilingual Tasks** | Qwen 2.5 14B | Mixtral |
| **Customer-Facing AI** | Gemma 2 9B | Mistral 7B |
| **Technical Docs** | Phi-3 14B | LLaMA 2 13B |
| **Data / JSON Output** | Qwen 2.5 14B | DeepSeek-R1 |
| **DevOps / Scripting** | Code Llama 13B | Mistral 7B |

---

## Infrastructure Notes

All eight models are hosted on the **BlueHarvest AI VPS infrastructure** running Ollama inside a Docker container on an OpenStack virtual machine (10.0.2.137). 

### Technical Specifications
- **Total Storage Required:** ~73 GB
- **Memory Management:** Models loaded into RAM on demand
- **Concurrent Models:** Typically 1-2 models in memory at any time
- **Access Authentication:** OpenStack Keystone
- **Login Portal:** cloud.blueharvestai.com (Horizon Dashboard)
- **Session Duration:** 8 hours (signed session cookie)
- **Chat History:** Stored server-side per user, persists across browsers and devices

### Access Information
- **LLM Interface:** https://lls.blueharvestai.com
- **Dashboard:** https://cloud.blueharvestai.com
- **Authentication:** OpenStack Keystone via Horizon

---

## Platform Benefits

### ✅ **Complete Data Privacy**
All models run locally on BlueHarvest AI infrastructure with zero external API calls.

### ✅ **Cost Efficiency**
No per-token pricing or API fees - unlimited usage within infrastructure capacity.

### ✅ **Customization**
Models can be fine-tuned or replaced based on organizational needs.

### ✅ **Compliance**
Full control over data residency and processing for regulatory compliance.

### ✅ **Offline Capability**
Models operate without internet connectivity once deployed.

---

## Support & Contact

**BlueHarvest AI Platform**  
**Website:** blueharvestai.com  
**LLM Service:** lls.blueharvestai.com  
**Dashboard:** cloud.blueharvestai.com

*For technical support or model recommendations, contact your Private Cloud administrator.*

---

**Document Version:** 1.0  
**Last Updated:** February 2026  
**Prepared by:** Private Cloud Intelligence Platform Team
