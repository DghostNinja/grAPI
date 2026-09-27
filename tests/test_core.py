import json

from grAPI.core import (
    COLORS,
    extract_script_calls,
    generate_postman_collection,
    is_api_request,
    is_graphql_request,
    is_ignored_path,
    is_potential_api,
    is_static_asset,
    load_openapi_spec,
    looks_like_api_host,
    method_color,
    normalize_method,
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


def test_api_host_heuristic():
    assert looks_like_api_host("https://api.graphqlbook.org/graphql")
    assert looks_like_api_host("https://gql.example.com/v1")
    assert looks_like_api_host("https://graphql.example.com/")
    assert not looks_like_api_host("https://example.com/api/users")
    assert not looks_like_api_host("https://cdn.example.com/v1/data")

    # XHR to an api.* host is an endpoint even without a path keyword
    assert is_api_request("https://api.partner.test/status", "xhr", False)
    assert not is_api_request("https://cdn.partner.test/status", "xhr", False)


def test_graphql_detected_from_payload_content_type_or_url():
    assert is_graphql_request(
        "https://gql.partner.test/execute",
        post_data='{"query":"{ books { id } }","variables":{}}',
    )
    assert is_graphql_request(
        "https://partner.test/execute", post_data="query { books { id } }"
    )
    assert is_graphql_request(
        "https://partner.test/execute", content_type="application/graphql"
    )
    assert is_graphql_request("https://partner.test/search?query=%7B__typename%7D")

    # not every JSON body is a GraphQL query
    assert not is_graphql_request(
        "https://partner.test/execute", post_data='{"search_query":"books"}'
    )
    assert not is_graphql_request(
        "https://partner.test/execute", post_data='{"name":"query"}'
    )
    assert not is_graphql_request("https://partner.test/execute", post_data='{"a":1}')


def test_graphql_api_request_beats_missing_url_keyword():
    assert is_api_request(
        "https://gql.partner.test/execute",
        "fetch",
        False,
        post_data='{"query":"{__typename}"}',
    )
    assert is_api_request(
        "https://partner.test/execute", "xhr", False, post_data="query { books }"
    )
    assert not is_api_request(
        "https://partner.test/execute", "xhr", False, post_data='{"a":1}'
    )


def test_telemetry_paths_are_ignored():
    for path in ("/i/v1/logs", "/i/v1/metrics", "/api/surveys/", "/api/product_tours/"):
        assert is_ignored_path("https://target.test" + path)
        assert not is_api_request("https://target.test" + path, "xhr", True)


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
        fetch(`/gql-endpoint`, {method: 'POST'});
        fetch('/dav-folder', {method: 'PROPFIND'});
        axios.put('/api/profile', {});
        const x = new XMLHttpRequest();
        x.open('DELETE', '/user/42');
        $.ajax({type: 'POST', url: '/transfer', data: {}});
    """
    calls = extract_script_calls(script)
    assert calls["/login"] == "POST"
    assert calls["/check_session"] == "GET"
    assert calls["/gql-endpoint"] == "POST"
    assert calls["/dav-folder"] == "PROPFIND"
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


def test_normalize_method_keeps_every_verb():
    assert normalize_method("get") == "GET"
    assert normalize_method(" patch ") == "PATCH"
    assert normalize_method("options") == "OPTIONS"
    assert normalize_method("trace") == "TRACE"
    assert normalize_method("QUERY") == "QUERY"       # GraphQL over HTTP
    assert normalize_method("PROPFIND") == "PROPFIND"  # WebDAV
    assert normalize_method(None) == "GET"
    assert normalize_method("!!!") == "GET"


def test_colors_cover_common_methods():
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        assert method in COLORS
    assert method_color("PATCH") == COLORS["PATCH"]
    assert method_color("PROPFIND") == COLORS["OTHER"]


def test_spec_loader_accepts_all_openapi_methods_and_skips_metadata(tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(
        json.dumps(
            {
                "paths": {
                    "/everything": {
                        "get": {},
                        "post": {},
                        "patch": {},
                        "trace": {},
                        "head": {},
                        "summary": "not a method",
                        "parameters": [],
                        "$ref": "#/components/x",
                    }
                }
            }
        )
    )
    endpoints = load_openapi_spec(spec.as_uri(), "https://target.test")
    assert endpoints["https://target.test/everything"] == {
        "GET",
        "POST",
        "PATCH",
        "TRACE",
        "HEAD",
    }


def test_postman_collection_keeps_uncommon_methods(tmp_path):
    out = tmp_path / "methods.postman.json"
    generate_postman_collection(
        {"https://target.test/dav": {"PROPFIND"}, "https://target.test/q": {"QUERY"}},
        str(out),
    )
    methods = {i["request"]["method"] for i in json.loads(out.read_text())["item"]}
    assert methods == {"PROPFIND", "QUERY"}
