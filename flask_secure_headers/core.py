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
				'include_subdomains':True,
				'preload':False
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

	def policyChange(self,updateParams,func):
		""" update defaultPolicy dict """
		for k,v in updateParams.items():
			k = k.replace('-','_')
			c = globals()[k](v)
			try:
				self.defaultPolicies[k] = getattr(c,func)(self.defaultPolicies[k])
			except Exception, e:
				raise

	def update(self,updateParams):
		""" add changes to existing policy """
		self.policyChange(updateParams,'update_policy')

	def rewrite(self,rewriteParams):
		""" rewrite existing policy to changes """
		self.policyChange(rewriteParams,'rewrite_policy')

	def wrapper(self,updateParams={}):
		""" create wrapper for flask app route """
		
		""" parse updates in wrapper call first and add to policy dict """
		policies = self.defaultPolicies
		if len(updateParams) > 0:
			for k,v in updateParams.items():
				k = k.replace('-','_')
				c = globals()[k](v)
				try:
					policies[k] = c.update_policy(self.defaultPolicies[k])
				except Exception, e:
					raise
		
		""" create headers list for flask wrapper """
		_headers = []
		for k,v in policies.items():
			if v is not None:
				_headers.append(globals()[k](v).create_header())
		
		def decorator(f):
			""" flask decorator to include headers """
			@wraps(f)
			def decorated_function(*args, **kwargs):
				resp = make_response(f(*args, **kwargs))
				h = resp.headers
				for header in _headers:
					for k,v in header.items():
						h[k] = v
				return resp
			return decorated_function
		return decorator
