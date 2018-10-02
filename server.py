#!/usr/bin/python3
import random
import string
import sys
from json import loads

from flask import Flask, Blueprint
from flask_restplus import Api, Resource, reqparse
import nltk
from nltk.corpus import stopwords
import pymysql
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
	return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


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
				sql = "SELECT id FROM secrets WHERE id=%s"
				cursor.execute(sql, args["key"])
				if cursor.fetchone() is None:
					return {"status": "error", "message": "Provided key does not match an existing key"}, 404

				sql = "UPDATE secrets SET second_secret=%s WHERE id=%s"
				cursor.execute(sql, (args["secret"], args["key"]))
				cursor.connection.commit()
				return {"status": "success", "message": "Added secret to key " + args["key"]}
			else:
				key = generate_key()
				sql = "INSERT INTO secrets (id, prime_secret) VALUES (%s, %s)"
				cursor.execute(sql, (key, args["secret"]))
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
			sql = "SELECT id FROM secrets WHERE id=%s"
			cursor.execute(sql, args["key"])
			if cursor.fetchone() is None:
				return {"status": "error", "message": "Provided key does not match an existing key"}, 404

			sql = "DELETE FROM secrets WHERE id=%s"
			cursor.execute(sql, args["key"])
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
			cursor.execute(sql, args["key"])
			res = cursor.fetchone()
			if res is None:
				return {"status": "error", "message": "Provided key does not match an existing key"}, 404

			lemmatizer = nltk.WordNetLemmatizer()
			secret1 = res[1].lower()
			secret2 = res[2].lower()
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
