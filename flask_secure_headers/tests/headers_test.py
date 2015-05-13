import unittest
from flask import Flask
from flask_secure_headers.headers import *


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
	def test_X_Content_Type_Options_fail_input(self):
		""" test invalid input for X_Content_Type_Options"""
		h = X_Content_Type_Options({'values':'nosniff'})
		with self.assertRaises(Exception):
			r = h.create_header()
	def test_X_Content_Type_Options_fail_parameter(self):	
		""" test invalid parameter for X_Content_Type_Options"""
		h = X_Content_Type_Options({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()	
	
	def test_X_Download_Options_pass(self):
		""" test valid X_Download_Options"""
		h = X_Download_Options({'value':'noopen'})
		r = h.create_header()
		self.assertEquals(r['X-Download-Options'],'noopen')
	def test_X_Download_Options_fail_input(self):
		""" test invalid input for X_Download_Options"""
		h = X_Download_Options({'values':'noopen'})
		with self.assertRaises(Exception):
			r = h.create_header()
	def test_X_Download_Options_fail_parameter(self):
		""" test invalid parameter for X_Download_Options"""
		h = X_Download_Options({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()	

	def test_X_Permitted_Cross_Domain_Policies_pass(self):
		""" test valid X_Permitted_Cross_Domain_Policies"""
		h = X_Permitted_Cross_Domain_Policies({'value':'master-only'})
		r = h.create_header()
		self.assertEquals(r['X-Permitted-Cross-Domain-Policies'],'master-only')
	def test_X_Permitted_Cross_Domain_Policies_fail_input(self):
		""" test invalid input for X_Permitted_Cross_Domain_Policies"""
		h = X_Permitted_Cross_Domain_Policies({'values':'master-only'})
		with self.assertRaises(Exception):
			r = h.create_header()
	def test_X_Permitted_Cross_Domain_Policies_fail_parameter(self):
		""" test invalid parameter for X_Permitted_Cross_Domain_Policies"""
		h = X_Permitted_Cross_Domain_Policies({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()	
					
	def test_X_XSS_Protection_pass_int(self):
		""" test valid X_XSS_Protection (int)"""
		h = X_XSS_Protection({'value':1})
		r = h.create_header()
		self.assertEquals(r['X-XSS-Protection'],'1')
	def test_X_XSS_Protection_pass_str(self):
		""" test valid X_XSS_Protection (str)"""
		h = X_XSS_Protection({'value':'1'})
		r = h.create_header()
		self.assertEquals(r['X-XSS-Protection'],'1')		
	def test_X_XSS_Protection_pass_second_param(self):
		""" test valid X_XSS_Protection (with second parameter)"""
		h = X_XSS_Protection({'value':'1','mode':'block'})
		r = h.create_header()
		self.assertEquals(r['X-XSS-Protection'],'1; mode=block')
	def test_X_XSS_Protection_pass_second_param_false(self):
		""" test valid X_XSS_Protection (with second parameter set to false)"""
		h = X_XSS_Protection({'value':'1','mode':False})
		r = h.create_header()
		self.assertEquals(r['X-XSS-Protection'],'1')		
	def test_X_XSS_Protection_fail_input(self):
		""" test invalid input for X_XSS_Protection"""
		h = X_XSS_Protection({'values':1})
		with self.assertRaises(Exception):
			r = h.create_header()
	def test_X_XSS_Protection_fail_paramater(self):
		""" test invalid paramater for X_XSS_Protection"""
		h = X_XSS_Protection({'value':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()
	def test_X_XSS_Protection_fail_second_paramater(self):
		""" test invalid second parameter for X_XSS_Protection """
		h = X_XSS_Protection({'value':'1','mode':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()

	def test_HSTS_pass_int(self):
		""" test valid HSTS (int)"""
		h = HSTS({'maxage':23})
		r = h.create_header()
		self.assertEquals(r['Strict-Transport-Security'],'maxage=23')
	def test_HSTS_pass_str(self):
		""" test valid HSTS (str)"""
		h = HSTS({'maxage':'23'})
		r = h.create_header()
		self.assertEquals(r['Strict-Transport-Security'],'maxage=23')		
	def test_HSTS_pass_second_param(self):
		""" test valid HSTS (with second parameter)"""
		h = HSTS({'maxage':23,'include_subdomains':True,'preload':False})
		r = h.create_header()
		self.assertEquals(r['Strict-Transport-Security'],'include_subdomains; maxage=23')		
	def test_HSTS_fail_input(self):
		""" test invalid input for HSTS """
		h = HSTS({'values':23})
		with self.assertRaises(Exception):
			r = h.create_header()
	def test_HSTS_fail_input_non_digit(self):
		""" test non-digit maxage value for HSTS """
		h = HSTS({'maxage':'fail'})
		with self.assertRaises(Exception):
			r = h.create_header()
	def test_HSTS_fail_non_boolean(self):
		""" test non-boolean include_subdomains value for HSTS """
		h = HSTS({'maxage':'23','include_subdomains':'Test'})
		with self.assertRaises(Exception):
			r = h.create_header()		

if __name__ == '__main__':
    unittest.main()		