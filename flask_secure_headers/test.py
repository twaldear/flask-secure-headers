import unittest
import tempfile
from flask import Flask
from headers import *
from core import Secure_Headers


class TestAppUseCase(unittest.TestCase):
	""" test header creation in flask app """
	def setUp(self):
		self.app = Flask(__name__)
		self.sh = Secure_Headers()
	def test_defaults(self):
		""" test header wrapper with default headers """
		@self.app.route('/')
		@self.sh.wrapper()
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEquals(result.headers.get('X-XSS-Protection'),'1; mode=block')
			self.assertEquals(result.headers.get('Strict-Transport-Security'),'max_age=31536000; include_subdomains')
			self.assertEquals(result.headers.get('X-Content-Type-Options'),'nosniff')
			self.assertEquals(result.headers.get('X-Permitted-Cross-Domain-Policies'),'none')
			self.assertEquals(result.headers.get('X-Download-Options'),'noopen')
			self.assertEquals(result.headers.get('X-Frame-Options'),'sameorigin')			
			self.assertEquals(result.headers.get('Content-Security-Policy'),"report-uri /csp_report; default-src 'self'")
	def test_update_function(self):
		""" test config update function """
		self.sh.update({'X_Permitted_Cross_Domain_Policies':{'value':'all'},'CSP':{'script-src':['self','code.jquery.com']}})
		@self.app.route('/')
		@self.sh.wrapper()
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEquals(result.headers.get('X-Permitted-Cross-Domain-Policies'),'all')
			self.assertEquals(result.headers.get('Content-Security-Policy'),"script-src 'self' code.jquery.com; report-uri /csp_report; default-src 'self'")
	def test_rewrite_function(self):
		""" test config rewrite function """
		self.sh.rewrite({'CSP':{'default-src':['none']}})
		@self.app.route('/')
		@self.sh.wrapper()
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEquals(result.headers.get('Content-Security-Policy'),"default-src 'none'")
	def test_wrapper_update_function(self):
		""" test updating policies from wrapper """
		self.sh.rewrite({'CSP':{'default-src':['none']}})
		@self.app.route('/')
		@self.sh.wrapper({'CSP':{'script-src':['self','code.jquery.com']},'X_Permitted_Cross_Domain_Policies':{'value':'none'},'X-XSS-Protection':{'value':1}})
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEquals(result.headers.get('X-Permitted-Cross-Domain-Policies'),'none')
			self.assertEquals(result.headers.get('Content-Security-Policy'),"script-src 'self' code.jquery.com; default-src 'none'")
			self.assertEquals(result.headers.get('X-XSS-Protection'),'1')
		@self.app.route('/test')
		@self.sh.wrapper({'CSP':{'script-src':['nonce-1234']}})
		def test(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/test')
			self.assertEquals(result.headers.get('Content-Security-Policy'),"script-src 'self' code.jquery.com 'nonce-1234'; default-src 'none'")
	def test_passing_none_value_rewrite(self):
		""" test removing header from update/rewrite """
		self.sh.rewrite({'CSP':None,'X_XSS_Protection':None})
		@self.app.route('/')	
		@self.sh.wrapper()
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEquals(result.headers.get('X-Permitted-Cross-Domain-Policies'),'none')
			self.assertEquals(result.headers.get('CSP'),None)
			self.assertEquals(result.headers.get('X-XSS-Protection'),None)
	def test_passing_none_value_wrapper(self):
		""" test removing policy from wrapper """
		@self.app.route('/')	
		@self.sh.wrapper({'CSP':None,'X-XSS-Protection':None})
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEquals(result.headers.get('X-Permitted-Cross-Domain-Policies'),'none')
			self.assertEquals(result.headers.get('CSP'),None)	
			self.assertEquals(result.headers.get('X-XSS-Protection'),None)

class TestPolicyCreation(unittest.TestCase):
	""" Test policy creation """
	def test_X_Frame_Options_pass(self):
		""" test valid X_Frame_Options"""
		h = X_Frame_Options({'value':'allow-from example.com'})
		r = h.create_header()
		self.assertEquals(r['X-Frame-Options'],'allow-from example.com')
	def test_X_Frame_Options_fail(self):
		""" test invalid input for X_Frame_Options"""
		h = X_Frame_Options({'values':'allow-from example.com'})
		with self.assertRaises(Exception):
			r = h.create_header()
		h = X_Frame_Options({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()		
	
	def test_X_Content_Type_Options_pass(self):
		""" test valid X_Content_Type_Options"""
		h = X_Content_Type_Options({'value':'nosniff'})
		r = h.create_header()
		self.assertEquals(r['X-Content-Type-Options'],'nosniff')
	def test_X_Content_Type_Options_fail(self):
		""" test invalid input for X_Content_Type_Options"""
		h = X_Content_Type_Options({'values':'nosniff'})
		with self.assertRaises(Exception):
			r = h.create_header()
		h = X_Content_Type_Options({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()	
	
	def test_X_Download_Options_pass(self):
		""" test valid X_Download_Options"""
		h = X_Download_Options({'value':'noopen'})
		r = h.create_header()
		self.assertEquals(r['X-Download-Options'],'noopen')
	def test_X_Download_Options_fail(self):
		""" test invalid input for X_Download_Options"""
		h = X_Download_Options({'values':'noopen'})
		with self.assertRaises(Exception):
			r = h.create_header()
		h = X_Download_Options({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()	

	def test_X_Permitted_Cross_Domain_Policies_pass(self):
		""" test valid X_Permitted_Cross_Domain_Policies"""
		h = X_Permitted_Cross_Domain_Policies({'value':'master-only'})
		r = h.create_header()
		self.assertEquals(r['X-Permitted-Cross-Domain-Policies'],'master-only')
	def test_X_Permitted_Cross_Domain_Policies_fail(self):
		""" test invalid input for X_Permitted_Cross_Domain_Policies"""
		h = X_Permitted_Cross_Domain_Policies({'values':'master-only'})
		with self.assertRaises(Exception):
			r = h.create_header()
		h = X_Permitted_Cross_Domain_Policies({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()	
					
	def test_X_XSS_Protection_pass(self):
		""" test valid X_XSS_Protection (int)"""
		h = X_XSS_Protection({'value':1})
		r = h.create_header()
		self.assertEquals(r['X-XSS-Protection'],'1')
		""" test valid X_XSS_Protection (str)"""
		h = X_XSS_Protection({'value':'1'})
		r = h.create_header()
		self.assertEquals(r['X-XSS-Protection'],'1')		
		""" test valid X_XSS_Protection (with parameter)"""
		h = X_XSS_Protection({'value':'1','mode':'block'})
		r = h.create_header()
		self.assertEquals(r['X-XSS-Protection'],'1; mode=block')		
	def test_X_XSS_Protection_fail(self):
		""" test invalid input for X_XSS_Protection"""
		h = X_XSS_Protection({'values':1})
		with self.assertRaises(Exception):
			r = h.create_header()
		h = X_XSS_Protection({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()
		""" test invalid second parameter """
		h = X_XSS_Protection({'value':'1','mode':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()

	def test_HSTS_pass(self):
		""" test valid HSTS (int)"""
		h = HSTS({'maxage':23})
		r = h.create_header()
		self.assertEquals(r['Strict-Transport-Security'],'maxage=23')
		""" test valid HSTS (str)"""
		h = HSTS({'maxage':'23'})
		r = h.create_header()
		self.assertEquals(r['Strict-Transport-Security'],'maxage=23')		
		""" test valid HSTS (with parameter)"""
		h = HSTS({'maxage':23,'include_subdomains':True,'preload':False})
		r = h.create_header()
		self.assertEquals(r['Strict-Transport-Security'],'include_subdomains; maxage=23')		
	def test_HSTS_fail(self):
		""" test invalid input for HSTS """
		h = HSTS({'values':23})
		with self.assertRaises(Exception):
			r = h.create_header()
		""" test non-digit value for maxage """
		h = HSTS({'maxage':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()
		""" test non-boolean for include_subdomains """
		h = HSTS({'maxage':'23','include_subdomains':'Test'})
		with self.assertRaises(Exception):
			r = h.create_header()		
	
	def test_CSP_pass(self):
		sh = Secure_Headers()
		defaultCSP = sh.defaultPolicies['CSP']
		""" test CSP policy update """
		h = CSP({'script-src':['self','code.jquery.com']}).update_policy(defaultCSP)
		self.assertEquals(h['script-src'],['self', 'code.jquery.com'])
		self.assertEquals(h['default-src'],['self'])
		self.assertEquals(h['img-src'],[])
		""" test CSP policy rewrite """
		h = CSP({'default-src':['none']}).rewrite_policy(defaultCSP)
		self.assertEquals(h['script-src'],[])
		self.assertEquals(h['default-src'],['none'])
		self.assertEquals(h['report-uri'],[])
		""" test CSP header creation """
		h = CSP({'default-src':['none']}).create_header()
		self.assertEquals(h['Content-Security-Policy'],"default-src 'none'")
		""" test CSP -report-only header creation """
		h = CSP({'default-src':['none'],'report-only':True}).create_header()
		self.assertEquals(h['Content-Security-Policy-Report-Only'],"default-src 'none'")		
	def test_CSP_fail(self):
		""" test invalid paramter for CSP update """
		with self.assertRaises(Exception):
			h = CSP({'test-src':['self','code.jquery.com']}).update_policy()

if __name__ == '__main__':
    unittest.main()
		