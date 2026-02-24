import config as node_config


def test_resolve_xray_executable_path_prefers_persistent_binary(monkeypatch, tmp_path):
    persistent_bin = tmp_path / "xray-core" / "xray"
    persistent_bin.parent.mkdir(parents=True, exist_ok=True)
    persistent_bin.write_text("binary", encoding="utf-8")

    monkeypatch.setattr(node_config, "PERSISTENT_XRAY_EXECUTABLE", persistent_bin)
    monkeypatch.setenv("XRAY_EXECUTABLE_PATH", "/opt/custom/xray")

    assert node_config._resolve_xray_executable_path() == str(persistent_bin)


def test_resolve_xray_executable_path_falls_back_to_configured_env(monkeypatch, tmp_path):
    persistent_bin = tmp_path / "xray-core" / "xray"
    monkeypatch.setattr(node_config, "PERSISTENT_XRAY_EXECUTABLE", persistent_bin)
    monkeypatch.setenv("XRAY_EXECUTABLE_PATH", "/opt/custom/xray")

    assert node_config._resolve_xray_executable_path() == "/opt/custom/xray"


def test_resolve_xray_assets_path_prefers_persistent_geo_files(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    xray_dir = data_dir / "xray-core"
    xray_dir.mkdir(parents=True, exist_ok=True)
    (xray_dir / "geosite.dat").write_bytes(b"geo")

    monkeypatch.setattr(node_config, "REBECCA_DATA_DIR", data_dir)
    monkeypatch.setattr(node_config, "PERSISTENT_XRAY_DIR", xray_dir)
    monkeypatch.setenv("XRAY_ASSETS_PATH", "/usr/local/share/xray")

    assert node_config._resolve_xray_assets_path() == str(xray_dir)


def test_resolve_xray_assets_path_falls_back_to_configured_env(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    xray_dir = data_dir / "xray-core"
    xray_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(node_config, "REBECCA_DATA_DIR", data_dir)
    monkeypatch.setattr(node_config, "PERSISTENT_XRAY_DIR", xray_dir)
    monkeypatch.setenv("XRAY_ASSETS_PATH", "/opt/custom/assets")

    assert node_config._resolve_xray_assets_path() == "/opt/custom/assets"
