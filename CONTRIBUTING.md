# Contributing to ByteGuardX

Thank you for your interest in contributing to ByteGuardX! This document provides guidelines for contributing to the project.

## 🚀 Quick Start

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/your-username/byteguardx.git
   cd byteguardx
   ```

3. **Set up development environment**
   ```bash
   # Install Python dependencies
   pip install -e ".[dev]"
   
   # Install frontend dependencies
   npm install
   
   # Run the application
   python run.py
   ```

## 🛠️ Development Setup

### Backend Development
```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8 byteguardx/
black byteguardx/

# Run type checking
mypy byteguardx/
```

### Frontend Development
```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Run linting
npm run lint

# Build for production
npm run build
```

## 📝 Code Style

### Python
- Follow PEP 8
- Use Black for formatting
- Add type hints
- Write docstrings for all functions
- Maximum line length: 88 characters

### JavaScript/React
- Use ESLint configuration
- Follow React best practices
- Use functional components with hooks
- Add PropTypes or TypeScript types

## 🧪 Testing

### Backend Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=byteguardx

# Run specific test file
pytest tests/test_scanners.py
```

### Frontend Tests
```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage
```

## 🔒 Security Guidelines

1. **Never commit secrets** - Use environment variables
2. **Validate all inputs** - Sanitize user data
3. **Follow OWASP guidelines** - Security best practices
4. **Test security features** - Include security tests

## 📋 Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write tests for new features
   - Update documentation
   - Follow code style guidelines

3. **Test your changes**
   ```bash
   # Backend tests
   pytest
   
   # Frontend tests
   npm test
   
   # Integration test
   python run.py
   ```

4. **Submit pull request**
   - Clear description of changes
   - Link to related issues
   - Include screenshots for UI changes

## 🐛 Bug Reports

When reporting bugs, please include:

- **Environment details** (OS, Python version, Node.js version)
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Error messages** or logs
- **Screenshots** if applicable

## 💡 Feature Requests

For new features:

- **Check existing issues** first
- **Describe the use case** clearly
- **Explain the benefit** to users
- **Consider implementation** complexity

## 📚 Documentation

- Update README.md for user-facing changes
- Add docstrings for new functions
- Update API documentation
- Include code examples

## 🏷️ Commit Messages

Use conventional commit format:

```
type(scope): description

feat(scanner): add new secret detection pattern
fix(api): resolve file upload timeout issue
docs(readme): update installation instructions
test(scanner): add unit tests for AI patterns
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `style`, `chore`

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🤝 Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain a professional environment

## 🆘 Getting Help

- **GitHub Issues** - For bugs and feature requests
- **Discussions** - For questions and ideas
- **Discord** - For real-time chat (coming soon)

## 🎯 Areas for Contribution

### High Priority
- [ ] Additional secret detection patterns
- [ ] More vulnerability databases
- [ ] Performance optimizations
- [ ] UI/UX improvements

### Medium Priority
- [ ] Additional language support
- [ ] Integration with CI/CD tools
- [ ] Advanced reporting features
- [ ] Mobile-responsive design

### Low Priority
- [ ] Plugin system
- [ ] Custom rule engine
- [ ] Advanced analytics
- [ ] Multi-language support

Thank you for contributing to ByteGuardX! 🔐
