# SecureBERT-specific external-reference review

## Primary sources

| Source | Identity | Supports | Does not support |
|---|---|---|---|
| SecureBERT paper | Ehsan Aghaei, Xi Niu, Waseem Shadid, Ehab Al-Shaer, “SecureBERT: A Domain-Specific Language Model for Cybersecurity,” arXiv:2204.02685 (2022), SecureComm proceedings (2023), https://arxiv.org/abs/2204.02685 | A published cybersecurity-domain language model, domain pretraining, and custom tokenizer methodology | This project's checkpoint identity, ModernBERT architecture, ATT&CK head, score calibration, Cowrie accuracy, robustness, or provenance |
| Official SecureBERT model card | `ehsanaghaei/SecureBERT`, https://huggingface.co/ehsanaghaei/SecureBERT | The official released model is RoBERTa-based and intended as a cybersecurity-domain masked language model | This project's 196-way classifier or task performance |
| ModernBERT paper | Benjamin Warner et al., “Smarter, Better, Faster, Longer: A Modern Bidirectional Encoder for Fast, Memory Efficient, and Long Context Finetuning and Inference,” arXiv:2412.13663 (2024), https://arxiv.org/abs/2412.13663 | ModernBERT architecture family and long-context design | This project's training lineage or classifier quality |
| Official ModernBERT base model card | Answer.AI, LightOn, `answerdotai/ModernBERT-base`, https://huggingface.co/answerdotai/ModernBERT-base | The base architecture dimensions/tokenizer conventions that match the local config | Proof that the private checkpoint was initialized from that exact base |
| Transformers ModernBERT documentation | Hugging Face, https://huggingface.co/docs/transformers/model_doc/modernbert | Executable `ModernBertForSequenceClassification` contract and raw logits semantics | Calibration, authority, or project quality |

## Reconciliation

The retained checkpoint's executable config says `model_type=modernbert` and
`ModernBertForSequenceClassification`; its special tokens, vocabulary dimensions, 22
layers, 768 hidden size, and 8,192 positions align with ModernBERT-base. The official
SecureBERT model is RoBERTa-based and has different architecture/tokenizer semantics.
Therefore the project-local name “SecureBERT” is historical terminology, not a factual
base-model identification.

Safe wording is: “a private project fine-tuned ModernBERT sequence classifier,
historically named SecureBERT, proposes one ATT&CK technique candidate from each
command fragment.” No external source validates the exact checkpoint.

