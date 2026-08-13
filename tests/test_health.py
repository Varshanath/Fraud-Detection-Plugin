def test_health_endpoint_status_code(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_health_endpoint_body(client):
    response = client.get("/health")
    assert response.json() == {"status": "healthy"}


def test_health_endpoint_content_type(client):
    response = client.get("/health")
    assert response.headers["content-type"] == "application/json"
