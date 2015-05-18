from flask import make_response
from functools import wraps
import os
import json
from headers import *

class Secure_Headers:
	def __init__(self):
		""" default policies for secure headers """
		self.defaultPolicies = {
			'CSP':{
				'default-src':['self'],
				'script-src':[],
				'img-src':[],
				'object-src':[],
				'plugin-src':[],
				'style-src':[],
				'media-src':[],
				'child-src':[],
				'connect-src':[],
				'base-uri':[],
				'font-src':[],
				'form-action':[],
				'frame-ancestors':[],
				'plugin-types':[],
				'referrer':[],
				'reflected-xss':[],
				'sandbox':[],
				'report-uri':['/csp_report'],
			},
			'HSTS':{
				'max_age':31536000,
				'includeSubdomains':True,
				'preload':False
			},
			'HPKP':{
				'max_age':5184000,
				'includeSubdomains':True,
				'report_uri':'/hpkp_report',
				'pins':[],
			},
			'X_Frame_Options':{
				'value':'sameorigin'
			},
			'X_XSS_Protection':{
				'value':1,
				'mode':'block'
			},
			'X_Content_Type_Options':{
				'value':'nosniff'
			},
			'X_Download_Options':{
				'value':'noopen'
			},
			'X_Permitted_Cross_Domain_Policies':{
				'value':'none'
			},

		}

	def _getHeaders(self, updateParams=None):
		""" create headers list for flask wrapper """
		if not updateParams:
			updateParams = {}
		policies = self.defaultPolicies
		if len(updateParams) > 0:
			for k,v in updateParams.items():
				k = k.replace('-','_')
				c = globals()[k](v)
				try:
					policies[k] = c.update_policy(self.defaultPolicies[k])
				except Exception, e:
					raise

		return [globals()[k](v).create_header()
				for k,v in policies.items() if v is not None]

	def _setRespHeader(self, resp, headers):
		for hdr in headers:
			for k,v in hdr.items():
				resp.headers[k] = v

	def policyChange(self, updateParams, func):
		""" update defaultPolicy dict """
		for k,v in updateParams.items():
			k = k.replace('-','_')
			c = globals()[k](v)
			try:
				self.defaultPolicies[k] = getattr(c,func)(self.defaultPolicies[k])
			except Exception, e:
				raise

	def update(self, updateParams):
		""" add changes to existing policy """
		self.policyChange(updateParams,'update_policy')

	def rewrite(self, rewriteParams):
		""" rewrite existing policy to changes """
		self.policyChange(rewriteParams,'rewrite_policy')

	def wrapper(self, updateParams=None):
		""" create wrapper for flask app route """
		def decorator(f):
			_headers = self._getHeaders(updateParams)
			""" flask decorator to include headers """
			@wraps(f)
			def decorated_function(*args, **kwargs):
				resp = make_response(f(*args, **kwargs))
				self._setRespHeader(resp, _headers)
				return resp
			return decorated_function
		return decorator

	def init_app(self, app, updateParams=None):
		_headers = self._getHeaders(updateParams)
		def add_sec_hdr(resp):
			self._setRespHeader(resp, _headers)
			return resp
		app.after_request(add_sec_hdr)