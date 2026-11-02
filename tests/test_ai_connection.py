from unittest.mock import Mock, patch
import pytest
import config
from schoolnet.ai_engine import ask_gemini, ask_provider

'''The tests folder is for checking that the application works correctly after code changes. It is not used by normal users while using the website.
It contains automated checks:
- test_detection.py
  Tests PCAP parsing, rule detection such as port scans and SSH brute force, threat scoring, timelines, and PDF generation.
- test_schoolnet.py
  Tests SchoolNet flows, device policies, ML baseline training/scoring, incidents, protocol checks, cryptography, and AI fallback.
- test_upload_selection.py
  Tests file upload, capture selection, report verification, secure reports, policy updates, and that old captures do not overwrite the selected one.
- test_ai_connection.py
  Tests the AI provider connection and safe handling of AI errors.'''


def test_gemini_request_and_multipart_response(monkeypatch):
    monkeypatch.setattr(config, 'GEMINI_API_KEY', 'test-secret')
    response = Mock(status_code=200)
    response.json.return_value = {'candidates': [{'content': {'parts': [
        {'thought': True, 'text': 'private reasoning'},
        {'text': '{"answer":"Three packets.",'}, {'text': '"references":["flow:1"]}'}]}}]}
    with patch('requests.post', return_value=response) as send:
        assert ask_gemini({}, 'Summarize')['answer'] == 'Three packets.'
        assert 'test-secret' not in send.call_args.args[0]
        assert send.call_args.kwargs['headers']['x-goog-api-key'] == 'test-secret'
        assert send.call_args.kwargs['timeout'] == (5, 40)


def test_provider_error_is_actionable(monkeypatch):
    monkeypatch.setattr(config, 'GEMINI_API_KEY', 'test-secret')
    with patch('requests.post', return_value=Mock(status_code=429)):
        with pytest.raises(RuntimeError, match='quota'):
            ask_gemini({}, 'Summarize')


def test_disabled_provider_never_calls_configured_keys(monkeypatch):
    monkeypatch.setattr(config, 'AI_PROVIDER', 'none')
    monkeypatch.setattr(config, 'GEMINI_API_KEY', 'test-secret')
    with patch('schoolnet.ai_engine.ask_gemini') as send:
        assert ask_provider({}, 'Question') is None
        send.assert_not_called()
