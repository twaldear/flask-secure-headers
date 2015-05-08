import re

class Simple_Header:
	""" base class for all headers except CSP """
	def check_valid(self):
		""" check if input is valid """
		for k,input in self.inputs.items():
			if k in self.valid_opts:
				for param in self.valid_opts[k]:
					if param is None:
						return True
					elif type(param) is str and '+' in param:
						if re.search(r'^'+param,str(input)):
							return True
					elif type(param) is bool and type(input) is bool:
						return True
					else:
						if str(input).lower() == str(param):
							return True
				raise ValueError("Invalid input for '%s' parameter. Options are: %s" % (k,' '.join(["'%s'," % str(o) for o in self.valid_opts[k]]) ))
			else:
				raise ValueError("Invalid parameter for '%s'. Params are: %s" % (self.__class__.__name__,', '.join(["'%s'" % p for p in self.valid_opts.keys()]) ))
	
	def update_policy(self,defaultHeaders):
		return self.inputs

	def rewrite_policy(self,defaultHeaders):
		return self.inputs
	
	def create_header(self):
		""" return header dict """
		try:
			self.check_valid()
			_header_list = []
			for k,v in self.inputs.items():
				if v is None:
					return  {self.__class__.__name__.replace('_','-'):None}
				elif k == 'value':
					_header_list.insert(0,str(v))
				elif isinstance(v,bool):
					if v is True:
						_header_list.append(k)
				else:
					_header_list.append('%s=%s' % (k,str(v)))
			return {self.__class__.__name__.replace('_','-'):'; '.join(_header_list)}
		except Exception, e:
			raise

class X_Frame_Options(Simple_Header):
	""" X_Frame_Options """
	def __init__(self,inputs,overide=None):
		self.valid_opts = {'value':['deny','sameorigin','allow-from .+']}
		self.inputs = inputs


class X_Content_Type_Options(Simple_Header):
	""" X_Content_Type_Options """
	def __init__(self,inputs,overide=None):
		self.valid_opts = {'value':['nosniff']}
		self.inputs = inputs
		

class X_Download_Options(Simple_Header):
	""" X_Download_Options """
	def __init__(self,inputs,overide=None):
		self.valid_opts = {'value':['noopen']}
		self.inputs = inputs

class X_Permitted_Cross_Domain_Policies(Simple_Header):
	""" X_Permitted_Cross_Domain_Policies """
	def __init__(self,inputs,overide=None):
		self.valid_opts = {'value':['all', 'none', 'master-only', 'by-content-type', 'by-ftp-filename']}
		self.inputs = inputs

class X_XSS_Protection(Simple_Header):
	""" X_XSS_Protection """
	def __init__(self,inputs,overide=None):
		self.valid_opts = {'value':[0,1],'mode':['block']}
		self.inputs = inputs

class HSTS(Simple_Header):
	""" HSTS """
	def __init__(self,inputs,overide=None):
		self.valid_opts = {'maxage':['[0-9]+'],'include_subdomains':[True,False],'preload':[True,False]}
		self.inputs = inputs
		self.__class__.__name__ = 'Strict-Transport-Security'

class CSP:
	def __init__(self, inputs):
		self.inputs = inputs
		self.header = 'Content-Security-Policy'
		if self.inputs is not None and 'report-only' in self.inputs:
			if self.inputs['report-only'] is True:
				self.header += '-Report-Only'
			del self.inputs['report-only']
	
	def check_valid(self,cspDefaultHeaders):
		if self.inputs is not None:
			for p,l in self.inputs.items():
				if p not in cspDefaultHeaders.keys() and p is not 'rewrite':		
					raise ValueError("Invalid parameter '%s'. Params are: %s" % (p,', '.join(["'%s'" % p for p in cspDefaultHeaders.keys()]) ))
	
	def update_policy(self,cspDefaultHeaders):
		""" add items to existing csp policies """
		try:
			self.check_valid(cspDefaultHeaders)
			if self.inputs is not None:
				for p,l in self.inputs.items():
					cspDefaultHeaders[p] = cspDefaultHeaders[p]+ list(set(self.inputs[p]) - set(cspDefaultHeaders[p]))
				return cspDefaultHeaders
			else:
				return self.inputs
		except Exception, e:
			raise
				
	def rewrite_policy(self,cspDefaultHeaders):
		""" fresh csp policy """
		try:
			self.check_valid(cspDefaultHeaders)		
			if self.inputs is not None:	
				for p,l in cspDefaultHeaders.items():
					if p in self.inputs:
						cspDefaultHeaders[p] = self.inputs[p]
					else:
						cspDefaultHeaders[p] = []
				return cspDefaultHeaders
			else:
				return self.inputs
		except Exception, e:
			raise

	def create_header(self):		
		""" return CSP header dict """		
		encapsulate =  re.compile("|".join(['^self','^none','^unsafe-inline','^unsafe-eval','^sha[\d]+-[\w=-]+','^nonce-[\w=-]+']))
		csp = {}
		for p,array in self.inputs.items():
			csp[p] = ' '.join(["'%s'" % l if encapsulate.match(l) else l for l in array])
			
		return {self.header:'; '.join(['%s %s' % (k, v) for k, v in csp.items() if v != ''])}
