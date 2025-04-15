# Contributing to CryptGuard

First, thank you for your interest in CryptGuard! Contributions from the community are a crucial part of making CryptGuard more secure, more usable, and more robust. This guide will help you understand our project’s practices for opening issues, creating pull requests, and participating in the discussion.

---

## Table of Contents

1. [How to Contribute](#how-to-contribute)
   - [Reporting Bugs](#reporting-bugs)
   - [Suggesting Features](#suggesting-features)
2. [Pull Requests](#pull-requests)
   - [Project Setup](#project-setup)
   - [Coding Guidelines](#coding-guidelines)
   - [Commit Messages](#commit-messages)
3. [Security Reports](#security-reports)
4. [Community and Conduct](#community-and-conduct)
5. [License](#license)

---

## How to Contribute

### Reporting Bugs

- **Search existing issues** to ensure your bug hasn’t already been reported.
- If not found, [open a new issue](../../issues/new) describing:
  1. **CryptGuard version** (or commit hash) you are using
  2. **Steps to reproduce** the bug
  3. **Expected behavior** vs. **actual behavior**
  4. Any **relevant error messages** or stack traces
- Provide as much detail as possible, including OS info and any logs.

### Suggesting Features

- Check the project’s [Roadmap](ROADMAP.md) or [open an issue](../../issues/new?template=feature_request.md) to propose your idea.
- Include:
  1. **A clear description** of the feature
  2. **Use cases** or examples of why it would be beneficial
  3. Any **alternative solutions** or workarounds you’ve tried

---

## Pull Requests

CryptGuard welcomes pull requests for bug fixes, improvements, and new features.

### Project Setup

1. **Fork** the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/CryptGuard.git
   cd CryptGuard
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Create a new branch** for your changes:
   ```bash
   git checkout -b my-feature
   ```

### Coding Guidelines

- **Python version**: We target Python 3.8+.
- **Style**: Follow [PEP 8](https://peps.python.org/pep-0008/).  
- **Naming**: Use descriptive function/class names.  
- **Tests**: If possible, add or update tests that cover your changes.

### Commit Messages

- Use clear, concise commit messages that explain **what** and **why**.  
- For example:
  ```
  Fix Argon2 fallback logic in argon_utils.py
  
  - Reduces memory_cost step by half on MemoryError.
  - Alerts user when fallback is exhausted.
  ```

When your work is ready, push the branch to your fork and [open a Pull Request](../../compare) against the main CryptGuard repository. Maintainers will review and provide feedback.

---

## Security Reports

If you discover a **security vulnerability**, we ask you to:
- **Do not** open a public issue or pull request describing it.
- Instead, please follow our [Security Policy](../SECURITY.md) for confidential disclosure.

---

## License

By contributing to CryptGuard, you accept and agree that your contributions are licensed under the [Apache 2.0 License](../LICENSE).

Thank you for helping make CryptGuard better!
