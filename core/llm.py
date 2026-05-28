"""ShadowNet - Local LLM Integration (Ollama)"""
import json
import subprocess
import urllib.request
import urllib.error

class LLMEngine:
    """Interface with local LLMs via Ollama for report writing and analysis"""
    
    def __init__(self, model="llama3.2:1b"):
        self.model = model
        self.available = False
        self._check_ollama()
    
    def _check_ollama(self):
        """Check if Ollama is running and model is available"""
        try:
            req = urllib.request.Request("http://localhost:11434/api/tags")
            resp = urllib.request.urlopen(req, timeout=3)
            data = json.loads(resp.read())
            models = [m['name'] for m in data.get('models', [])]
            
            if any(self.model in m for m in models):
                self.available = True
                return True
            
            # Try to find any usable model
            if models:
                self.model = models[0]
                self.available = True
                return True
            
            return False
        except Exception:
            return False
    
    def pull_model(self):
        """Pull the model via Ollama"""
        try:
            subprocess.run(['ollama', 'pull', self.model], 
                         capture_output=True, timeout=300)
            self.available = True
            return True
        except Exception:
            return False
    
    def analyze(self, prompt, system_prompt=None):
        """Send a prompt to the LLM and get response"""
        if not self.available:
            return None
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 1024,
            }
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            req = urllib.request.Request(
                "http://localhost:11434/api/generate",
                data=json.dumps(payload).encode(),
                headers={'Content-Type': 'application/json'}
            )
            resp = urllib.request.urlopen(req, timeout=60)
            result = json.loads(resp.read())
            return result.get('response', '')
        except Exception:
            return None
    
    def write_report_summary(self, target, findings):
        """Generate a natural language summary of findings"""
        if not self.available:
            return None
        
        finding_summaries = []
        for f in findings[:15]:
            finding_summaries.append(f"- [{f.get('severity','info').upper()}] {f.get('title','')}")
        
        prompt = f"""Analyze these security scan results for {target} and write a brief executive summary:

Findings ({len(findings)} total):
{chr(10).join(finding_summaries)}

Write a short paragraph summarizing the security posture, the most critical issues, and recommended next steps. Be direct and technical."""
        
        return self.analyze(prompt, system_prompt="You are a penetration testing report writer. Be concise and technical.")
    
    def suggest_remediation(self, finding_title, description):
        """Get AI-suggested remediation for a specific finding"""
        if not self.available:
            return None
        
        prompt = f"""Finding: {finding_title}
Description: {description}

Suggest specific remediation steps for this security issue. Be actionable."""
        
        return self.analyze(prompt, system_prompt="You are a security engineer providing remediation advice.")

