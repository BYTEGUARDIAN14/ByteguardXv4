# ByteGuardX Folder Upload Feature Guide

## 🚀 Overview

ByteGuardX now supports both **individual file uploads** and **complete folder uploads** with enterprise-grade security, cross-platform compatibility, and a 2GB total upload limit.

## ✨ New Features

### 📁 **Folder Upload Support**
- Upload entire directories with all subdirectories
- Recursive file processing maintaining folder structure
- Support for up to **10,000 files** per upload session
- **2GB total size limit** across all files

### 🔒 **Enhanced Security**
- Path traversal protection (`../`, absolute paths)
- File type validation (50+ supported code file types)
- Individual file size limit: **500MB per file**
- Malicious file detection (executables, archives, binaries)
- Input sanitization and XSS prevention

### 🎯 **Smart File Processing**
- Real-time upload progress tracking
- Batch validation with detailed error reporting
- Memory-efficient streaming for large uploads
- Automatic cleanup of temporary files

## 🛠️ Technical Implementation

### Frontend (React)

#### Upload Modes
```jsx
// Toggle between single file and folder upload
const [uploadMode, setUploadMode] = useState('file'); // 'file' or 'folder'

// Single file upload
<input
  type="file"
  onChange={handleFileUpload}
  accept=".py,.js,.jsx,.ts,.tsx,.java,.cs,.php,.go,.rb,.cpp,.c,.h,.json,.yaml,.yml"
/>

// Folder upload
<input
  type="file"
  onChange={handleFolderUpload}
  webkitdirectory=""
  mozdirectory=""
  directory=""
  multiple
/>
```

#### Security Validation
```javascript
const UPLOAD_CONSTANTS = {
  MAX_TOTAL_SIZE: 2 * 1024 * 1024 * 1024, // 2GB
  MAX_INDIVIDUAL_FILE_SIZE: 500 * 1024 * 1024, // 500MB per file
  MAX_FILE_COUNT: 10000,
  ALLOWED_EXTENSIONS: [
    'py', 'js', 'jsx', 'ts', 'tsx', 'java', 'cpp', 'c', 'h', 'cs', 'php', 'rb',
    'go', 'rs', 'swift', 'kt', 'scala', 'json', 'xml', 'yml', 'yaml', 'txt',
    'md', 'rst', 'dockerfile', 'sh', 'bat', 'ps1', 'sql', 'html', 'css', 'scss'
  ],
  BLOCKED_EXTENSIONS: [
    'exe', 'dll', 'so', 'dylib', 'bin', 'app', 'deb', 'rpm', 'msi', 'dmg',
    'iso', 'img', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'
  ]
};
```

### Backend (Flask)

#### API Endpoints

**Single File Upload:**
```
POST /api/scan/file
Content-Type: multipart/form-data
Rate Limit: 10 requests/minute
```

**Folder Upload:**
```
POST /api/scan/folder
Content-Type: multipart/form-data
Rate Limit: 5 requests/minute
```

#### Security Features
```python
def validate_filename(filename):
    """Comprehensive filename validation"""
    # Check for dangerous patterns
    dangerous_patterns = [/\.\./g, /^\//, /^\\/, /\0/, /[\x00-\x1f\x7f-\x9f]/]
    
    # Validate file extension
    allowed_extensions = {...}
    blocked_extensions = {...}
    
    return validation_result

def scan_folder_internal(files, form_data):
    """Process multiple files with security validation"""
    # Validate total size (2GB limit)
    # Check individual file sizes (500MB limit)
    # Validate file count (10,000 limit)
    # Process each file securely
```

## 🔧 Usage Examples

### Basic File Upload
```javascript
// Select and upload a single file
const handleFileUpload = async (event) => {
  const file = event.target.files[0];
  
  // Validation happens automatically
  // File is processed and scanned
  // Results displayed in UI
};
```

### Folder Upload
```javascript
// Select and upload entire folder
const handleFolderUpload = async (event) => {
  const files = Array.from(event.target.files);
  
  // Recursive folder structure maintained
  // All files validated and processed
  // Comprehensive scan results provided
};
```

### API Response Format
```json
{
  "scan_id": "folder_scan_1640995200",
  "status": "completed",
  "findings": [
    {
      "title": "Potential Hardcoded Password",
      "description": "Found potential hardcoded password in code",
      "severity": "high",
      "confidence": 0.8,
      "file_path": "src/config.py",
      "line_number": 15,
      "scanner_name": "basic_scanner"
    }
  ],
  "summary": {
    "total_files": 25,
    "total_issues": 3,
    "high_severity": 1,
    "medium_severity": 2,
    "low_severity": 0,
    "total_size_mb": 15.7
  },
  "metadata": {
    "scanner_version": "1.0.0",
    "scan_mode": "comprehensive",
    "upload_type": "multiple_files"
  }
}
```

## 🛡️ Security Measures

### File Validation
- **Extension Whitelist**: Only approved code file types
- **Size Limits**: 500MB per file, 2GB total
- **Path Sanitization**: Prevents directory traversal
- **Content Validation**: Checks for malicious patterns

### Upload Protection
- **Rate Limiting**: Prevents abuse and DoS attacks
- **Memory Management**: Efficient streaming for large files
- **Temporary Storage**: Secure cleanup after processing
- **Error Handling**: Detailed validation feedback

### Cross-Platform Security
- **Windows**: Handles backslash paths and drive letters
- **macOS/Linux**: Unix-style path validation
- **Unicode Support**: Proper encoding handling
- **Symlink Protection**: Prevents symbolic link attacks

## 🧪 Testing

### Run Security Tests
```bash
# Test folder upload functionality
python test_folder_upload.py

# Test with custom server URL
python test_folder_upload.py --url http://localhost:5000
```

### Test Scenarios Covered
- ✅ Single file upload validation
- ✅ Multiple file upload processing
- ✅ Large file rejection (>500MB)
- ✅ Invalid file type blocking
- ✅ Path traversal protection
- ✅ Total size limit enforcement (2GB)
- ✅ File count limit validation (10,000 files)

## 🚀 Deployment

### Development
```bash
# Start backend server
python byteguardx_auth_api_server.py

# Start frontend (separate terminal)
npm run dev
```

### Production
```bash
# Run security audit
python security_audit.py

# Deploy application
python deploy.py

# Start production server
gunicorn -w 4 -b 0.0.0.0:5000 byteguardx_auth_api_server:app
```

## 📊 Performance Considerations

### Memory Usage
- **Streaming Upload**: Files processed in chunks
- **Temporary Storage**: Automatic cleanup after scan
- **Memory Limits**: Configurable per deployment

### Network Optimization
- **Compression**: Client-side compression for large folders
- **Progress Tracking**: Real-time upload progress
- **Error Recovery**: Graceful handling of network issues

### Scalability
- **Rate Limiting**: Prevents server overload
- **Resource Monitoring**: CPU and memory tracking
- **Load Balancing**: Ready for horizontal scaling

## 🎨 UI/UX Features

### Design Consistency
- **Black Background**: Maintained throughout interface
- **Cyan Interactions**: Hover effects and active states
- **Glassmorphism**: Transparent UI elements preserved
- **Responsive Design**: Works on all screen sizes

### User Experience
- **Drag & Drop**: Intuitive file/folder selection
- **Progress Indicators**: Real-time upload feedback
- **Error Messages**: Clear validation feedback
- **File Preview**: Shows selected files and structure

## 🔍 Troubleshooting

### Common Issues
1. **Upload Fails**: Check file types and sizes
2. **Slow Upload**: Large folders may take time
3. **Memory Errors**: Reduce file count or size
4. **Path Errors**: Avoid special characters in filenames

### Debug Mode
```bash
# Enable debug logging
export FLASK_ENV=development
export DEBUG=true
python byteguardx_auth_api_server.py
```

## 📈 Future Enhancements

### Planned Features
- **Resume Upload**: Continue interrupted uploads
- **Compression**: Automatic file compression
- **Cloud Storage**: Direct cloud provider integration
- **Batch Processing**: Queue-based large folder processing

### Performance Improvements
- **Parallel Processing**: Multi-threaded scanning
- **Caching**: Intelligent result caching
- **CDN Integration**: Faster file delivery
- **Database Optimization**: Enhanced query performance

---

## 🎉 Conclusion

ByteGuardX now provides enterprise-grade file and folder upload capabilities with comprehensive security, excellent performance, and seamless user experience while maintaining the signature black/cyan design aesthetic.

For support or questions, please refer to the main documentation or contact the development team.
