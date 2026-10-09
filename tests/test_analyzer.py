import unittest
from analyzer import analyze_message, _links

class AnalyzerTests(unittest.TestCase):
    def test_urgent_credential_link_message(self):
        r = analyze_message('URGENT: Your account will be blocked. Click https://example.invalid and enter your OTP.')
        ids = {x['id'] for x in r['indicators']}
        self.assertIn('urgency_pressure', ids)
        self.assertIn('credential_request', ids)
        self.assertIn('link_pressure', ids)
    def test_ordinary_appointment_has_no_indicators(self):
        self.assertEqual(analyze_message('Your appointment is confirmed for tomorrow at 10 AM.')['indicators'], [])
    def test_otp_warning_is_not_credential_request(self):
        self.assertNotIn('credential_request', {x['id'] for x in analyze_message('Do not share your OTP with anyone.')['indicators']})
    def test_payment_word_alone_not_flagged(self):
        self.assertNotIn('payment_request', {x['id'] for x in analyze_message('Your payment was received successfully.')['indicators']})
    def test_does_not_echo_input(self):
        result = analyze_message('private test phrase')
        self.assertNotIn('text', result)
    def test_link_is_defanged_and_not_fetched(self):
        link = _links('Visit https://example.com/path')[0]
        self.assertIn('[.]', link['display'])
    def test_language_fallback(self):
        self.assertEqual(analyze_message('hello', 'unknown')['language'], 'en')
    def test_tamil_credential_rule(self):
        ids = {x['id'] for x in analyze_message('உங்கள் OTP ஐ பகிரவும்', 'ta')['indicators']}
        self.assertIn('credential_request', ids)

if __name__ == '__main__': unittest.main()
