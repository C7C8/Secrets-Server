#!/usr/bin/python3
import base64
import random
import string
import sys
from json import loads

import bcrypt
import nltk
import pymysql
from flask import Flask, Blueprint
from flask_restplus import Api, Resource, reqparse
from nltk.corpus import stopwords
from cryptography.fernet import Fernet

stop_words = set(stopwords.words('english'))


def perror(*args, **kwargs):
	"""I needed to write to stderr and I'm lazy. Sue me."""
	print(*args, file=sys.stderr, **kwargs)


# Default conf so the server can start even if conf.json is missing
conf = {
	"host": "localhost",
	"port": 3306,
	"user": "secrets",
	"password": "secrets",
	"schema": "secrets"
}

try:
	with open("conf.json", "r") as file:
		conf = loads(file.read())
except FileNotFoundError:
	perror("Failed to load conf.json file!")


# Flask+db setup
app = Flask(__name__)
apiV1 = Blueprint("api", __name__)
api = Api(apiV1, title="Secrets API", description="API for exchanging secrets")
ns = api.namespace("api", description="Secrets API endpoint")


def connect_db(host, port, user, password, schema):
	"""Still lazy!"""
	return pymysql.connect(host=host, port=port, user=user, password=password, database=schema)


def generate_key():
	"""Generate a random 6-letter uppercase alphanumeric key for users to use. The key is short on purpose -- enough to
	guarantee that probability of a collision is negligible, but the key is easily readable and sharable.

	Yes, I'm still lazy."""
	return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=12))


def hash_key(key):
	"""RED ALERT! BAD CRYPTO!

	So... there's a kinda good reason for this. We want to be able to hash the key so we can perform lookups using the
	hash, while the actual encryption key remains unknown. That means we have to be able to generate this hash on the
	fly and feed it to the db to use as a primary key, which we can't do if the salt is randomized each time we hash the
	key generated for the user. Hence, the constant salt. Yes, this is a bad thing and it does weaken the security here,
	but we need it. It's still better than using a fast hashing algorithm like sha3-512 (which was also considered).

	Also, I'm STILL lazy. This is just here because I don't want to keep copying that salt everywhere."""
	return bcrypt.hashpw(key.encode('utf-8'), "$2a$12$V5udsWyGOcr6RouVN/.Bc.")


def encrypt(message, key):
	"""Encrypt a message with Fernet -- 128-bit CBC AES"""
	# Must pad the key so Fernet doesn't throw a hissy fit
	key = base64.urlsafe_b64encode((key + 'aaaaaaaaaaaaaaaaaaaa').encode('utf-8'))
	f = Fernet(key)
	return f.encrypt(message.encode('utf-8'))


def decrypt(message, key):
	"""Decrypt a message"""
	# Must pad the key so Fernet doesn't throw a hissy fit.
	key = base64.urlsafe_b64encode((key + 'aaaaaaaaaaaaaaaaaaaa').encode('utf-8'))
	f = Fernet(key)
	return f.decrypt(message.encode('utf-8')).decode('utf-8')


@ns.route("/secrets")
class Secrets(Resource):
	def post(self):
		"""Submit a new secret or add to an existing one; this is a POST both for technical and practical reasons.
		Technically this does create a resource on the server, but the real reason is that a POST allows a body whereas
		a GET does not, and we do NOT want this information in the query string, or it'd show up in the server logs"""
		parser = reqparse.RequestParser()
		parser.add_argument("secret", help="Secret keywords", required=True, type=str)
		parser.add_argument("key", help="Secret key", required=False, type=str)
		args = parser.parse_args()

		with connect_db(**conf) as cursor:
			if args["key"] is not None:
				# Put second secret in database, but check if the secret key exists first. If it doesn't, error.
				hkey = hash_key(args["key"])
				secret = encrypt(args["secret"], args["key"])

				sql = "SELECT id FROM secrets WHERE id=%s"
				cursor.execute(sql, hkey)
				if cursor.fetchone() is None:
					return {"status": "error", "message": "Provided key does not match an existing key"}, 404

				sql = "UPDATE secrets SET second_secret=%s WHERE id=%s"
				cursor.execute(sql, (secret, hkey))
				cursor.connection.commit()
				return {"status": "success", "message": "Added secret to key " + args["key"]}
			else:
				key = generate_key()
				hkey = hash_key(key)
				secret = encrypt(args["secret"], key)
				sql = "INSERT INTO secrets (id, first_secret) VALUES (%s, %s)"
				cursor.execute(sql, (hkey, secret))
				cursor.connection.commit()
				return {"status": "success", "message": "Added secret", "key": key}, 200

	def delete(self):
		"""Delete any given secret pair using just the key. This allows either partner to delete their secret on a whim."""
		parser = reqparse.RequestParser()
		parser.add_argument("key", required=True, type=str)
		args = parser.parse_args()

		with connect_db(**conf) as cursor:
			# Check if the provided key matches an existing key or not. Technically we don't need to do this, but it's
			# useful to provide the user with a better status message
			hkey = hash_key(args["key"])
			sql = "SELECT id FROM secrets WHERE id=%s"
			cursor.execute(sql, hkey)
			if cursor.fetchone() is None:
				return {"status": "error", "message": "Provided key does not match an existing key"}, 404

			sql = "DELETE FROM secrets WHERE id=%s"
			cursor.execute(sql, hkey)
			cursor.connection.commit()
			return {"status": "success", "message": "Deleted secret " + args["key"]}

	def get(self):
		"""Using a key, get a boolean that tells you whether your secret is confirmed or not. Keyword matching
		percentage is also shown."""
		parser = reqparse.RequestParser()
		parser.add_argument("key", required=True, type=str)
		args = parser.parse_args()

		with connect_db(**conf) as cursor:
			sql = "SELECT * FROM secrets WHERE id=%s"
			cursor.execute(sql, hash_key(args["key"]))
			res = cursor.fetchone()
			if res is None:
				return {"status": "error", "message": "Provided key does not match an existing key"}, 404

			lemmatizer = nltk.WordNetLemmatizer()
			secret1 = decrypt(res[1], args["key"])
			secret2 = decrypt(res[2], args["key"])
			secret1_tokenized = set(lemmatizer.lemmatize(t) for t in nltk.tokenize.casual_tokenize(secret1))
			secret2_tokenized = set(lemmatizer.lemmatize(t) for t in nltk.tokenize.casual_tokenize(secret2))

			# Get direct word overlap count, without eliminating stop words
			direct_overlap = len(secret1_tokenized & secret2_tokenized)

			# Calculate word set intersection to find a percent match, without eliminating stop words
			percent_overlap = float(len(secret1_tokenized & secret2_tokenized)) / len(secret1_tokenized | secret2_tokenized) * 100

			# Calculate word set intersection to find a percent match, this time with stop words defined
			secret1_tokenized = set(filter(lambda tk: tk not in stop_words, secret1_tokenized))
			secret2_tokenized = set(filter(lambda tk: tk not in stop_words, secret2_tokenized))

			# Get direct overlap count, without stop words
			direct_overlap_kw = len(secret1_tokenized & secret2_tokenized)

			# Get percent overlap, without stop words
			percent_overlap_kw = float(len(secret1_tokenized & secret2_tokenized)) / len(secret1_tokenized | secret2_tokenized) * 100

			return {
				"status": "success",
				"message": "Textual analysis contained",
				"direct_comparison": secret1 == secret2,
				"word_overlap": direct_overlap,
				"percent_overlap": percent_overlap,
				"keyword_overlap": direct_overlap_kw,
				"keyword_percent_overlap": percent_overlap_kw
			}, 200


app.register_blueprint(apiV1)
if __name__ == "__main__":
	app.run(port=5000)
