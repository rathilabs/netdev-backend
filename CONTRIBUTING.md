# Contributing to NetDevs Backend

First off, thank you for considering contributing to NetDevs Backend! It's people like you that make NetDevs Pro a great tool for the networking community.

## 🚀 How Can I Contribute?

### Reporting Bugs
*   Check the [Issues](https://github.com/rathilabs/netdev-backend/issues) page to see if the bug has already been reported.
*   If not, open a new issue. Include a clear title, a description of the bug, steps to reproduce it, and the expected vs. actual behavior.

### Suggesting Enhancements
*   Open an issue with the tag "enhancement".
*   Describe the feature you'd like to see and why it would be useful.

### Pull Requests
1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/amazing-feature`).
3.  Make your changes.
4.  Ensure your code follows our standards (see below).
5.  Commit your changes (`git commit -m 'Add some amazing feature'`).
6.  Push to the branch (`git push origin feature/amazing-feature`).
7.  Open a Pull Request.

## 🛠️ Development Standards

### Code Style
- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code.
- Use meaningful variable and function names.
- Ensure every new function/class has a docstring explaining its purpose, arguments, and return values.

### Structure
- **Core Logic**: Keep raw socket and protocol assembly in `src/injector.py`.
- **API/Server**: Handle WebSocket commands and lifecycle in `src/server.py`.
- **Entry Point**: Always use `main.py` as the entry point. Do not put business logic in `main.py`.

### Testing
- Before submitting a PR, test your changes on at least one platform (Linux or macOS).
- If you add a new command, update the `ICD.md` documentation accordingly.

## 📜 License
By contributing, you agree that your contributions will be licensed under the project's open-source license.

---

*Thank you for helping us build better networking tools!*
