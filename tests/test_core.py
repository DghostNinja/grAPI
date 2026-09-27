import json

from grAPI.core import (
    extract_script_calls,
    generate_postman_collection,
    is_api_request,
    is_ignored_path,
    is_potential_api,
    is_static_asset,
    load_openapi_spec,
    save_output,
)

def test_is_potential_api():
    assert is_potential_api("/api/users")
    assert is_potential_api("https://example.com/graphql")
    assert not is_potential_api("https://example.com/home")
    assert is_potential_api("/v1/data")


def test_static_assets_are_not_api_requests():
    font = "https://fonts.gstatic.com/s/outfit/v15/QGYvz_MVcBeNP4NJtEtq.woff2"
    assert is_static_asset(font)
    assert is_potential_api(font)  # keyword heuristic alone still matches
    assert not is_api_request(font, "font", same_origin=False)
    assert not is_api_request("https://target.test/static/style.css", "stylesheet", True)
    assert not is_api_request("https://target.test/assets/app.js", "script", True)


def test_infrastructure_beacons_are_ignored():
    assert is_ignored_path("https://target.test/cdn-cgi/rum?")
    assert not is_api_request("https://target.test/cdn-cgi/rum?", "fetch", True)


def test_same_origin_xhr_is_always_captured():
    assert is_api_request("https://target.test/login", "xhr", True)
    assert is_api_request("https://target.test/fetch/transfer", "fetch", True)
    assert not is_api_request("https://target.test/about", "document", True)


def test_cross_origin_still_requires_api_keyword():
    assert is_api_request("https://api.partner.test/v2/orders", "xhr", False)
    assert not is_api_request("https://cdn.partner.test/app.bundle", "xhr", False)


def test_load_openapi_spec(tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(
        json.dumps(
            {
                "paths": {
                    "/login": {"post": {"responses": {}}},
                    "/api/transactions": {"get": {}},
                    "/transfer": {"post": {}, "options": {}},
                    "/not-a-method": {"parameters": []},
                }
            }
        )
    )
    endpoints = load_openapi_spec(spec.as_uri(), "https://vulnbank.org/login")
    assert endpoints["https://vulnbank.org/login"] == {"POST"}
    assert endpoints["https://vulnbank.org/api/transactions"] == {"GET"}
    assert endpoints["https://vulnbank.org/transfer"] == {"POST", "OPTIONS"}
    assert "https://vulnbank.org/not-a-method" not in endpoints


def test_extract_script_calls_finds_call_sites_without_api_keyword():
    script = """
        const response = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });
        fetch('/check_session');
        axios.put('/api/profile', {});
        const x = new XMLHttpRequest();
        x.open('DELETE', '/user/42');
        $.ajax({type: 'POST', url: '/transfer', data: {}});
    """
    calls = extract_script_calls(script)
    assert calls["/login"] == "POST"
    assert calls["/check_session"] == "GET"
    assert calls["/api/profile"] == "PUT"
    assert calls["/user/42"] == "DELETE"
    assert calls["/transfer"] == "POST"


def test_save_output_accepts_method_map(tmp_path):
    endpoints = {"https://target.test/login": {"POST"}, "https://target.test/api/x": {"GET"}}
    out = tmp_path / "out.txt"
    save_output(endpoints, str(out))
    assert out.read_text().splitlines() == [
        "https://target.test/api/x",
        "https://target.test/login",
    ]


def test_postman_collection_uses_real_methods(tmp_path):
    endpoints = {
        "https://target.test/login": {"POST"},
        "https://target.test/api/v1/items/{item_id}": {"GET", "DELETE"},
    }
    out = tmp_path / "out.postman.json"
    generate_postman_collection(endpoints, str(out))
    collection = json.loads(out.read_text())
    requests = {(i["request"]["method"], i["request"]["url"]["raw"]) for i in collection["item"]}
    assert ("POST", "https://target.test/login") in requests
    assert ("GET", "https://target.test/api/v1/items/:item_id") in requests
    assert ("DELETE", "https://target.test/api/v1/items/:item_id") in requests


def test_postman_collection_accepts_legacy_plain_set(tmp_path):
    out = tmp_path / "legacy.postman.json"
    generate_postman_collection({"https://target.test/api/x"}, str(out))
    collection = json.loads(out.read_text())
    assert collection["item"][0]["request"]["method"] == "GET"
    assert collection["item"][0]["request"]["url"]["raw"] == "https://target.test/api/x"
