# FieldSure Validation Protocol

This document is a proposed engineering validation workflow. It is not evidence that a real forensic kit has been validated.

## Dataset design

Use a unique `sample_id` for every test image and a `batch_id` for physical sample/batch provenance. Keep development/tuning data separate from an untouched held-out set. Do not allow the same physical sample or batch to cross dataset splits unless the study design explicitly supports it.

## Ground truth

Use a laboratory-confirmed reference outcome or another predefined authoritative reference method. Record the reference source and decision date/version.

## Preprocessing lock

Freeze the kit profile, reference-card specification, image-quality gates and preprocessing/classification version before final held-out evaluation.

## Report

At minimum report the confusion matrix and, per class, sensitivity, specificity, PPV, NPV and F1. Report sample counts and appropriate confidence intervals. For clustered, repeated or multi-reader studies, use a statistical method matched to the study design rather than treating all images as independent observations.

## Robustness

Stratify testing across relevant cameras, operators, lighting conditions, viewing angles and capture quality conditions. Explicitly record failure/inconclusive cases and retake rates.

## Acceptance

Define acceptance thresholds before the final held-out test. Do not select thresholds after seeing held-out outcomes.
