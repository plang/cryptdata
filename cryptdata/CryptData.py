# Copyright (C) 2013 Philippe Lang <philippe.lang@cromagnon.ch>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Philippe Lang <philippe.lang@cromagnon.ch>

import re
from subprocess import Popen, PIPE

from trac.core import *

from trac.wiki.macros import WikiMacroBase
from trac.wiki.api import IWikiPageManipulator

from trac.web.api import IRequestFilter
from trac.web.chrome import ITemplateProvider
from trac.web.chrome import add_script
from trac.web.chrome import add_stylesheet
from trac.web.chrome import add_meta

from trac.config import Option

class CryptDataMacro(WikiMacroBase):
    """Expands the CryptData Macro into a javascript enabled RSA decoder."""
    def expand_macro(self, formatter, name, text):
        params = text.split(',')
        encrypted_data_type = params[0]
        encrypted_data = params[1]

        if encrypted_data_type == "password":
            t = """
                <span class="cryptdata-password">
                    <a href="javascript:void(0)">Show encrypted password</a>
                    <span class="hide encrypted_password">%s</span>
                </span>
            """ % (encrypted_data)

        return t

class CryptDataValidator(Component):
    """Intercepts the creation of encrypted data and crypts it."""
    implements(IWikiPageManipulator)

    public_key_path = Option('cryptdata', 'public_key_path', '', doc='RSA public key path')

    def prepare_wiki_page(self, req, page, fields):
        return

    def validate_wiki_page(self, req, page):
        # Looping through all CPassword() blocs occurences
        password_pattern = re.compile(r'(\[\[[cC][pP]assword\(.*\)\]\])')
        for (password) in re.findall(password_pattern, page.text):
            # Getting password, and encrypting it
            string_unencoded = re.sub( r'\[\[[cC][pP]assword\((.*)\)\]\]', r'\1', password)
            p1 = Popen(["echo", string_unencoded], stdout=PIPE)
            p2 = Popen(["openssl", "rsautl", "-encrypt", "-pubin", "-inkey", self.public_key_path], stdin=p1.stdout, stdout=PIPE)
            p3 = Popen(["base64", "-w", "0"], stdin=p2.stdout, stdout=PIPE)
            string_encoded = p3.communicate()[0]
            # Doing the replacement
            replacement_pattern = re.compile(r'\[\[[cC][pP]assword\(%s\)\]\]' % string_unencoded)
            page.text = re.sub(replacement_pattern, "[[CryptData(password," + string_encoded + ")]]", page.text)
        return []

class CryptDataHeaderScript(Component):
    """Fills the header with the necessary JS libraries, CSS & RSA key."""
    implements(IRequestFilter, ITemplateProvider)

    private_key_path = Option('cryptdata', 'private_key_path', '', doc="RSA private key path")

    def get_htdocs_dirs(self):
        from pkg_resources import resource_filename
        return [('hw', resource_filename(__name__, 'htdocs'))]

    def get_templates_dirs(self):
        return []

    def pre_process_request(self, req, handler):
        return handler

    def post_process_request(self, req, template, data, content_type):
        # pidCrypt
        add_script(req, "hw/js/pidcrypt/pidcrypt.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/pidcrypt_util.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/md5.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/aes_core.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/aes_cbc.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/asn1.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/jsbn.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/rng.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/prng4.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/rsa.js", "text/javascript")
        add_script(req, "hw/js/pidcrypt/certparser.js", "text/javascript")

        # Vex
        add_script(req, "hw/js/vex.combined.min.js", "text/javascript")
        add_stylesheet(req, "hw/css/vex.css", "text/css")
        add_stylesheet(req, "hw/css/vex-theme-default.css", "text/css")
        add_stylesheet(req, "hw/css/cryptdata-password.css", "text/css")

        # Plugin code
        add_script(req, "hw/js/cryptdata-password.js", "text/javascript")

        # Private key
        p = Popen(["more", self.private_key_path], stdout=PIPE)
        key = p.communicate()[0]
        add_meta(req, key, None, "private_key_encoded")
	
        return (template, data, content_type)
