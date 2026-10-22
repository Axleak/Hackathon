const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const PORT = process.env.PORT || 3000;


app.use(bodyParser.json());
app.use(express.static('public'));


// 1. Hàm phân tích mã nguồn cơ bản (Static Scan Engine)
function scanCodeIntegrity(codeSnippet) {
  const suspiciousPatterns = [
    /eval\(/i,                      // Thực thi chuỗi code độc hại
    /child_process/i,               // Gọi lệnh hệ thống ngầm
    /btoa\(|atob\(/i,               // Mã hóa/giải mã base64 nghi vấn
    /https?:\/\/.*\.sh/i            // Tải file script thực thi ngoài
  ];


  let detectedRisks = [];
  suspiciousPatterns.forEach((pattern) => {
    if (pattern.test(codeSnippet)) {
      detectedRisks.push(`Phát hiện mẫu nghi vấn: ${pattern}`);
    }
  });


  return {
    isSafe: detectedRisks.length === 0,
    issues: detectedRisks
  };
}


// 2. API Quét Code & Khởi tạo Luồng TideCloak
app.post('/api/scan', async (req, res) => {
  const { repoUrl, codeSnippet } = req.body;


  if (!codeSnippet) {
    return res.status(400).json({ error: "Vui lòng cung cấp mã nguồn để kiểm tra." });
  }


  // Bước A: Quét mã nguồn
  const scanResult = scanCodeIntegrity(codeSnippet);


  // Bước B: Tích hợp TideCloak (Emergent Authority Verification)
  // Trong prototype thực tế, bạn gọi API/SDK của TideCloak hoặc Tide MCP ở đây
  const tideCloakProof = {
    action: "ISSUE_SECURITY_ATTESTATION",
    policyId: "POLICY_NO_SINGLE_ADMIN_OVERRIDE",
    status: "PROTECTED_BY_EMERGENT_AUTHORITY",
    timestamp: new Date().toISOString()
  };


  res.json({
    repository: repoUrl || "Direct Snippet Scan",
    scanResult: scanResult,
    tideCloakAttestation: tideCloakProof
  });
});


app.listen(PORT, () => {
  console.log(`CodeTrust prototype running at http://localhost:${PORT}`);
});

