#!/usr/bin/python
import ConfigParser
import os
import subprocess
import sys
import logging
import traceback

try:
  from urllib.request import urlopen # Python 3
except ImportError:
  from urllib2 import urlopen # Python 2

sys.path.append('./acme-tiny')

import acme_tiny

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

config = ConfigParser.ConfigParser({'file_key': '%(domain)s.key.pem', 'file_csr': '%(domain)s.csr.pem', 'file_crt': '%(domain)s.crt.pem', 'file_intermediate': '%(domain)s.intermediate.pem', 'file_chained': '%(domain)s.chained.pem', 'file_cfg': '%(domain)s.cfg.pem', 'san': '%(domain)s'})
config.read('renew.ini')

domains = config.get("general",  "domains").split()
accountkey =  config.get("general", "accountkey")
acmedir = config.get("general", "challengedir");
intermediateurl = config.get("general", "intermediateurl");
opensslcfg = config.get("general", "opensslcfg");

reload_services = 0;

LOGGER.info("DOMAINS: %s" % ( domains ))
LOGGER.info("ACCOUNTKEY: %s" % ( accountkey ))
LOGGER.info("ACMEDIR: %s" % ( acmedir ));
LOGGER.info("INTERMEDIATEURL: %s" % ( intermediateurl ));


if not os.path.isdir(acmedir):
    os.mkdir(acmedir)

if not os.path.isfile(accountkey):
    print "no valid accountkey"
    raise

for domain in domains:
  if not config.has_section(domain):
    config.add_section(domain)
  key_file = config.get(domain, 'file_key', 0, {'domain': domain })
  csr_file = config.get(domain, 'file_csr', 0, {'domain': domain })
  crt_file = config.get(domain, 'file_crt', 0, {'domain': domain })
  cfg_file = config.get(domain, 'file_cfg', 0, {'domain': domain })

  intermediate_file = config.get(domain, 'file_intermediate', 0, {'domain': domain })
  chained_file = config.get(domain, 'file_chained', 0, {'domain': domain })

  sans = config.get(domain, 'san', 0, {'domain': domain }).split()
  renew_cert = 1;

  print "DOMAIN:", domain, csr_file, crt_file, intermediate_file, chained_file, key_file

  if not os.path.isfile(csr_file):
    if not os.path.isfile(key_file):
      process = subprocess.Popen("openssl genrsa -out %s 4096" % (key_file), shell=True, stdout=subprocess.PIPE)
      stdout,stderr = process.communicate()
      LOGGER.info(stderr);

      if process.returncode != 0:
        print("could not generate key");

      if not os.path.isfile(key_file):
        print("key not found and could not be created...")
        continue

    san_text_array = [];

    for san in sans:
      san_text_array.append("DNS:"+san);

    LOGGER.info(san_text_array);
 
    file_fd = open(opensslcfg, "r")
    cfg_text = file_fd.read()
    file_fd.close()

    file_fd = open(cfg_file, "w")
    file_fd.write(cfg_text)
    file_fd.write("[SAN]\nsubjectAltName=%s" % (','.join([str(x) for x in san_text_array])))
    file_fd.close()

    process = subprocess.Popen('openssl req -new -sha256 -key %s -subj "/" -reqexts SAN -config %s -out %s' % (key_file, cfg_file, csr_file), shell=True, stdout=subprocess.PIPE)
    stdout,stderr = process.communicate()
    LOGGER.info(stdout)
    LOGGER.info(stderr);

    if process.returncode != 0:
      LOGGER.error("could not generate csr");

    if not os.path.isfile(csr_file):
      LOGGER.error("csr not found and could not be created...")
      continue

  if os.path.isfile(crt_file):
    process = subprocess.Popen("openssl x509 -checkend 2592000 -noout -enddate -in %s" % (crt_file), shell=True, stdout=subprocess.PIPE)
    stdout,stderr = process.communicate()
      
    if process.returncode == 0:
      LOGGER.info("EXPIRY: %s %s" % (domain, stdout.strip()))
      renew_cert = 0

  if not renew_cert:
    continue

  try: 
    crt_text = acme_tiny.get_crt(accountkey, csr_file, acmedir, log=LOGGER)

    if len(crt_text) <= 0:
      LOGGER.error("certificate could not be retrieved :/")
      raise
  
    file_fd = open(crt_file, "w")
    file_fd.write(crt_text)
    file_fd.close()

    response = urlopen(intermediateurl)

    intermediate_text = response.read()

    if len(intermediate_text) <= 0:
      LOGGER.error("intermediate cert could not be retrieved :/")
      raise

    file_fd = open(intermediate_file, "w")
    file_fd.write(intermediate_text)
    file_fd.close()


    file_fd = open(chained_file, "w")
    file_fd.write(crt_text)
    file_fd.write(intermediate_text)
    file_fd.close()

  except:
   traceback.print_exc()

  LOGGER.info("CERT FETCHED: %s" % ( domain ))
if reload_services:
  LOGGER.info("TODO: reload services")
