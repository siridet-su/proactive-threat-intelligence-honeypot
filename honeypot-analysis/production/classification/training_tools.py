"""SecureBERT training helpers extracted from the notebook.

These are not used by always-on production services. They preserve the
notebook workflow for preparing Cowrie auto-labeled examples and fine-tuning
the classifier head when you intentionally run a training job.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from production.classification.classification_pipeline import auto_label_commands


def prepare_finetune_dataset(
    labeled_data: Sequence[Dict[str, Any]],
    existing_csv_path: Optional[str] = None,
    val_split: float = 0.15,
    min_samples_per_class: int = 10,
    random_seed: int = 42,
):
    try:
        import pandas as pd
        from sklearn.model_selection import train_test_split
    except ImportError as exc:
        raise RuntimeError("Fine-tune dataset preparation requires pandas and scikit-learn.") from exc

    new_df = pd.DataFrame([
        {
            "Technique ID": row["label"],
            "Technique Name": row.get("label_name", "Unknown"),
            "Sentences": row["text"],
            "source": row.get("source", "cowrie_auto_labeled"),
        }
        for row in labeled_data
    ])
    if existing_csv_path:
        try:
            existing_df = pd.read_csv(existing_csv_path)
            existing_df["source"] = "mitre_prose"
            combined = pd.concat([existing_df, new_df], ignore_index=True)
        except Exception:
            combined = new_df
    else:
        combined = new_df

    counts = combined["Technique ID"].value_counts()
    valid_ttps = counts[counts >= min_samples_per_class].index
    combined = combined[combined["Technique ID"].isin(valid_ttps)].reset_index(drop=True)
    if combined.empty:
        raise ValueError("No TTP class has enough samples for fine-tuning.")
    return train_test_split(
        combined,
        test_size=val_split,
        stratify=combined["Technique ID"],
        random_state=random_seed,
    )


def finetune_bert_classifier(
    model,
    tokenizer,
    train_df,
    val_df,
    output_dir: str,
    num_epochs: int = 3,
    learning_rate: float = 2e-5,
    freeze_base: bool = True,
):
    try:
        import numpy as np
        import torch
        from torch.utils.data import Dataset
        from transformers import Trainer, TrainingArguments
    except ImportError as exc:
        raise RuntimeError("Fine-tuning requires torch, transformers, and numpy.") from exc

    label2id = {value: int(key) for key, value in model.config.id2label.items()}

    class CowrieDataset(Dataset):
        def __init__(self, df):
            valid = df[df["Technique ID"].isin(label2id)].reset_index(drop=True)
            self.texts = valid["Sentences"].tolist()
            self.labels = [label2id[tid] for tid in valid["Technique ID"]]

        def __len__(self):
            return len(self.texts)

        def __getitem__(self, idx):
            encoded = tokenizer(
                self.texts[idx],
                padding="max_length",
                truncation=True,
                max_length=256,
                return_tensors="pt",
            )
            return {
                "input_ids": encoded["input_ids"].squeeze(),
                "attention_mask": encoded["attention_mask"].squeeze(),
                "labels": torch.tensor(self.labels[idx]),
            }

    if freeze_base:
        for name, param in model.named_parameters():
            if "classifier" not in name and "pooler" not in name:
                param.requires_grad = False

    args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=num_epochs,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=32,
        learning_rate=learning_rate,
        warmup_ratio=0.1,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=20,
        report_to="none",
        fp16=torch.cuda.is_available(),
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=1)
        return {"accuracy": round(float((preds == labels).mean()), 4)}

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=CowrieDataset(train_df),
        eval_dataset=CowrieDataset(val_df),
        compute_metrics=compute_metrics,
    )
    trainer.train()
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    return trainer
