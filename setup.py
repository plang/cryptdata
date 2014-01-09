from setuptools import setup

setup(
	name = 'CryptData',
	version = '0.9.3',
	maintainer = 'Philippe Lang',
	maintainer_email = 'philippe.lang@cromagnon.ch',
	description = 'Encrypts / Decrypts data with an RSA keypair',
	license = 'GPL3',

	packages = ['cryptdata'],
	package_data = {
		'cryptdata': [	
			'htdocs/js/*.js', 
			'htdocs/js/pidcrypt/*.js',
			'htdocs/css/*.css'
		]
	},

	entry_points = {
		'trac.plugins': [
			'cryptdata.CryptData = cryptdata.CryptData',
		]
	}
)
