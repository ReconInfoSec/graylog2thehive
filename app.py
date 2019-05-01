from app import app
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.options |= ssl.OP_NO_SSLv2
context.options |= ssl.OP_NO_SSLv3
context.load_cert_chain('cert.pem', 'privkey.pem')
context.load_verify_locations('fullchain.pem')

app.run(debug = False, threaded=True, host='0.0.0.0', port=5000, passthrough_errors=True, ssl_context=context)
