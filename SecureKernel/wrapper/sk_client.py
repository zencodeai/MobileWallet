import requests

from sk_utils import SKConfig


class RestClient:

	def __init__(self, cfg: SKConfig):
		# Constructor
		self._prefix = f'{cfg.protocol}{cfg.host}:{cfg.port}{cfg.prefix}/'

	def _get_url(self, endpoint: str) -> str:
		# Get URL from configuration and parameters
		return f'{self._prefix}{endpoint}'

	@classmethod
	def _get_api_headers(cls, auth_headers: dict = {}) -> dict:
		# Add authentication headers to API request headers
		api_headers = {'Accept': 'application/json'}
		api_headers.update(auth_headers)
		return api_headers

	@classmethod
	def assert_satus_code(cls, rsp: requests.Response, value: list[int]):
		if rsp.status_code not in value:
			raise Exception('Request failed {} : {}'.format(rsp.status_code, rsp.text))

	def post(self, endpoint: str, headers: dict) -> requests.Response:
		# Post request
		return requests.post(self._get_url(endpoint), headers=headers)

	def api_get(self, endpoint: str) -> requests.Response:
		# API GET request
		api_headers = self._get_api_headers()
		return requests.get(self._get_url(endpoint), headers=api_headers)

	def api_post(self, endpoint: str, payload: dict) -> requests.Response:
		# API POST request
		api_headers = self._get_api_headers()
		return requests.post(self._get_url(endpoint), headers=api_headers, json=payload)

	def api_put(self, endpoint: str, payload: dict) -> requests.Response:
		# API PUT request
		api_headers = self._get_api_headers()
		return requests.put(self._get_url(endpoint), headers=api_headers, json=payload)

	def api_delete(self, endpoint: str) -> requests.Response:
		# API DELETE request
		api_headers = self._get_api_headers()
		return requests.delete(self._get_url(endpoint), headers=api_headers)

	def api_post_abs(self, endpoint: str, payload: dict) -> requests.Response:
		# API POST request
		api_headers = self._get_api_headers()
		return requests.post(endpoint, headers=api_headers, json=payload)
