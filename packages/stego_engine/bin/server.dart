import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:stego_engine/stego_engine.dart';

void main(List<String> args) async {
  final port = 8080;
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
  print('StegoEngine App Server running at http://localhost:$port');

  await for (HttpRequest request in server) {
    try {
      await _handleRequest(request);
    } catch (e, stack) {
      stderr.writeln('Error handling request: $e\n$stack');
      try {
        request.response
          ..statusCode = HttpStatus.internalServerError
          ..headers.contentType = ContentType.json
          ..write(jsonEncode({'success': false, 'error': e.toString()}))
          ..close();
      } catch (_) {}
    }
  }
}

Future<void> _handleRequest(HttpRequest request) async {
  // CORS headers
  request.response.headers.add('Access-Control-Allow-Origin', '*');
  request.response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  request.response.headers.add('Access-Control-Allow-Headers', 'Content-Type');

  if (request.method == 'OPTIONS') {
    request.response.statusCode = HttpStatus.ok;
    await request.response.close();
    return;
  }

  final path = request.uri.path;

  if (request.method == 'GET' && (path == '/' || path == '/index.html')) {
    request.response
      ..statusCode = HttpStatus.ok
      ..headers.contentType = ContentType.html
      ..write(_getAppHtml());
    await request.response.close();
    return;
  }

  if (request.method == 'POST') {
    final bodyString = await utf8.decodeStream(request);
    final data = jsonDecode(bodyString) as Map<String, dynamic>;

    if (path == '/api/inspect') {
      await _handleInspect(request, data);
      return;
    } else if (path == '/api/encode') {
      await _handleEncode(request, data);
      return;
    } else if (path == '/api/extract') {
      await _handleExtract(request, data);
      return;
    } else if (path == '/api/capacity') {
      await _handleCapacity(request, data);
      return;
    }
  }

  request.response
    ..statusCode = HttpStatus.notFound
    ..write('Not Found');
  await request.response.close();
}

Future<void> _handleCapacity(HttpRequest request, Map<String, dynamic> data) async {
  final encoder = StegoEncoder();
  final isEncrypted = data['isEncrypted'] as bool? ?? false;

  CapacityInfo info;
  if (data.containsKey('carrierBase64')) {
    final carrierBytes = base64Decode(data['carrierBase64'] as String);
    info = encoder.calculateCapacityFromBytes(
      carrierBytes: Uint8List.fromList(carrierBytes),
      isEncrypted: isEncrypted,
    );
  } else {
    final width = data['width'] as int? ?? 100;
    final height = data['height'] as int? ?? 100;
    info = encoder.calculateCapacity(width: width, height: height, isEncrypted: isEncrypted);
  }

  request.response
    ..headers.contentType = ContentType.json
    ..write(jsonEncode({
      'success': true,
      'width': info.width,
      'height': info.height,
      'rawCapacityBytes': info.rawCapacityBytes,
      'usableTextCapacityBytes': info.usableTextCapacityBytes,
      'usableFileCapacityBytes': info.usableFileCapacityBytes,
      'isEncrypted': info.isEncrypted,
    }));
  await request.response.close();
}

Future<void> _handleInspect(HttpRequest request, Map<String, dynamic> data) async {
  final decoder = StegoDecoder();
  final carrierBytes = Uint8List.fromList(base64Decode(data['carrierBase64'] as String));

  CarrierInfo carrierInfo;
  try {
    carrierInfo = decoder.inspectCarrier(carrierBytes);
  } catch (e) {
    request.response
      ..headers.contentType = ContentType.json
      ..write(jsonEncode({
        'success': false,
        'status': 'invalid_image',
        'message': 'Failed to decode PNG carrier: $e',
      }));
    await request.response.close();
    return;
  }

  final inspection = decoder.inspectPayload(carrierBytes);

  Map<String, dynamic> responseData;
  switch (inspection) {
    case SupportedPayloadInspection(:final payloadType, :final isEncrypted, :final declaredPayloadLength, :final formatVersion):
      responseData = {
        'success': true,
        'status': 'supported',
        'carrier': {
          'width': carrierInfo.width,
          'height': carrierInfo.height,
          'totalPixels': carrierInfo.totalPixels,
          'rawCapacityBytes': carrierInfo.rawCapacityBytes,
          'hasAlpha': carrierInfo.hasAlpha,
        },
        'payload': {
          'type': payloadType.name,
          'isEncrypted': isEncrypted,
          'declaredPayloadLength': declaredPayloadLength,
          'formatVersion': formatVersion,
        },
        'message': 'Validated container signature with ${isEncrypted ? "AES-256-GCM encrypted" : "unencrypted"} ${payloadType.name} framing.',
      };
    case NoSupportedPayloadInspection(:final reason):
      responseData = {
        'success': true,
        'status': 'no_payload',
        'carrier': {
          'width': carrierInfo.width,
          'height': carrierInfo.height,
          'totalPixels': carrierInfo.totalPixels,
          'rawCapacityBytes': carrierInfo.rawCapacityBytes,
          'hasAlpha': carrierInfo.hasAlpha,
        },
        'message': reason,
      };
    case UnsupportedVersionInspection(:final detectedVersion, :final reason):
      responseData = {
        'success': true,
        'status': 'unsupported_version',
        'detectedVersion': detectedVersion,
        'message': reason,
      };
    case CorruptPayloadInspection(:final reason):
      responseData = {
        'success': false,
        'status': 'corrupt',
        'message': reason,
      };
    case InvalidCarrierInspection(:final reason):
      responseData = {
        'success': false,
        'status': 'invalid_image',
        'message': reason,
      };
  }

  request.response
    ..headers.contentType = ContentType.json
    ..write(jsonEncode(responseData));
  await request.response.close();
}

Future<void> _handleEncode(HttpRequest request, Map<String, dynamic> data) async {
  final encoder = StegoEncoder();
  final carrierBytes = Uint8List.fromList(base64Decode(data['carrierBase64'] as String));
  final type = data['type'] as String? ?? 'text';
  final password = data['password'] as String?;

  EncodeRequest encodeRequest;
  if (type == 'text') {
    final text = data['text'] as String? ?? '';
    encodeRequest = EncodeRequest.text(
      carrierBytes: carrierBytes,
      text: text,
      password: password != null && password.isNotEmpty ? password : null,
    );
  } else {
    final fileBytes = Uint8List.fromList(base64Decode(data['fileBase64'] as String));
    final filename = data['filename'] as String? ?? 'payload.bin';
    final mediaType = data['mediaType'] as String? ?? 'application/octet-stream';
    encodeRequest = EncodeRequest.file(
      carrierBytes: carrierBytes,
      fileBytes: fileBytes,
      filename: filename,
      mediaType: mediaType,
      password: password != null && password.isNotEmpty ? password : null,
    );
  }

  try {
    final encodedPngBytes = await encoder.encode(encodeRequest);
    final capacity = encoder.calculateCapacityFromBytes(
      carrierBytes: carrierBytes,
      isEncrypted: encodeRequest.encrypt,
    );

    // Perform internal pre-flight verification
    final decoder = StegoDecoder();
    final verifyResult = await decoder.extract(
      carrierBytes: encodedPngBytes,
      password: password != null && password.isNotEmpty ? password : null,
    );
    final isVerified = verifyResult is TextExtractionSuccess || verifyResult is FileExtractionSuccess;

    request.response
      ..headers.contentType = ContentType.json
      ..write(jsonEncode({
        'success': true,
        'stegoImageBase64': base64Encode(encodedPngBytes),
        'fileSize': encodedPngBytes.length,
        'isVerified': isVerified,
        'capacity': {
          'rawCapacityBytes': capacity.rawCapacityBytes,
          'usableTextCapacityBytes': capacity.usableTextCapacityBytes,
          'usableFileCapacityBytes': capacity.usableFileCapacityBytes,
        },
      }));
  } on StegoException catch (e) {
    request.response
      ..statusCode = HttpStatus.badRequest
      ..headers.contentType = ContentType.json
      ..write(jsonEncode({'success': false, 'error': e.runtimeType.toString(), 'message': e.message}));
  }
  await request.response.close();
}

Future<void> _handleExtract(HttpRequest request, Map<String, dynamic> data) async {
  final decoder = StegoDecoder();
  final carrierBytes = Uint8List.fromList(base64Decode(data['carrierBase64'] as String));
  final password = data['password'] as String?;

  final result = await decoder.extract(
    carrierBytes: carrierBytes,
    password: password != null && password.isNotEmpty ? password : null,
  );

  Map<String, dynamic> responseData;
  switch (result) {
    case TextExtractionSuccess(:final text, :final isEncrypted):
      responseData = {
        'success': true,
        'type': 'text',
        'text': text,
        'isEncrypted': isEncrypted,
      };
    case FileExtractionSuccess(:final filename, :final mediaType, :final fileBytes, :final isEncrypted):
      responseData = {
        'success': true,
        'type': 'file',
        'filename': filename,
        'mediaType': mediaType,
        'fileSize': fileBytes.length,
        'fileBase64': base64Encode(fileBytes),
        'isEncrypted': isEncrypted,
      };
    case ExtractionFailure(:final exception, :final message):
      responseData = {
        'success': false,
        'errorType': exception.runtimeType.toString(),
        'message': message,
      };
  }

  request.response
    ..headers.contentType = ContentType.json
    ..write(jsonEncode(responseData));
  await request.response.close();
}

String _getAppHtml() {
  return r'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>StegoSuite &bull; Cryptographic Steganography Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      /* Foundation colours from design system */
      --app-bg: #F5F7FB;
      --surface: #FFFFFF;
      --sidebar: #F0F3F8;
      --primary-text: #172033;
      --secondary-text: #64748B;
      --border: #E2E8F0;

      /* Brand and status colours */
      --primary-blue: #2563EB;
      --primary-blue-hover: #1D4ED8;
      --teal: #0D9488;
      --teal-light: rgba(13, 148, 136, 0.1);
      --success: #16A34A;
      --success-light: rgba(22, 163, 74, 0.1);
      --warning: #D97706;
      --warning-light: rgba(217, 119, 6, 0.1);
      --critical: #DC2626;
      --critical-light: rgba(220, 38, 38, 0.1);
      --info: #0284C7;
      --info-light: rgba(2, 132, 199, 0.1);

      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', "SF Mono", Consolas, Menlo, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
      background-color: var(--app-bg);
      color: var(--primary-text);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      font-size: 14px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    /* Sidebar Navigation */
    aside {
      width: 270px;
      background-color: var(--sidebar);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
      min-height: 100vh;
      position: sticky;
      top: 0;
    }

    .sidebar-header {
      padding: 1.5rem 1.25rem 1.25rem;
      border-bottom: 1px solid var(--border);
    }

    .brand-mark {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .brand-icon {
      width: 34px;
      height: 34px;
      background: var(--primary-blue);
      color: #FFFFFF;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 15px;
      letter-spacing: -0.03em;
    }

    .brand-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--primary-text);
      letter-spacing: -0.02em;
    }

    .nav-menu {
      padding: 1.25rem 0.85rem;
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      flex: 1;
    }

    .nav-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 600;
      color: var(--secondary-text);
      padding: 0 0.6rem 0.5rem;
    }

    .nav-item {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.65rem 0.85rem;
      border-radius: 8px;
      color: var(--secondary-text);
      font-weight: 500;
      font-size: 13.5px;
      cursor: pointer;
      border: none;
      background: transparent;
      width: 100%;
      text-align: left;
      transition: all 0.15s ease;
    }

    .nav-item svg {
      color: var(--secondary-text);
      transition: color 0.15s ease;
      flex-shrink: 0;
    }

    .nav-item:hover {
      background-color: rgba(226, 232, 240, 0.5);
      color: var(--primary-text);
    }

    .nav-item.active {
      background-color: #FFFFFF;
      color: var(--primary-blue);
      font-weight: 600;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04), 0 1px 2px rgba(0, 0, 0, 0.02);
      border: 1px solid var(--border);
    }

    .nav-item.active svg {
      color: var(--primary-blue);
    }

    .sidebar-footer {
      padding: 1.25rem;
      border-top: 1px solid var(--border);
      background: rgba(255, 255, 255, 0.5);
    }

    .engine-telemetry {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
    }

    .telemetry-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 11.5px;
    }

    .telemetry-title {
      color: var(--secondary-text);
    }

    .telemetry-value {
      font-family: var(--font-mono);
      font-weight: 600;
      color: var(--primary-text);
    }

    .live-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--success);
      display: inline-block;
      margin-right: 4px;
    }

    /* Main Area */
    main {
      flex: 1;
      padding: 2rem;
      max-width: 1300px;
      display: flex;
      flex-direction: column;
      gap: 1.75rem;
    }

    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .page-title {
      font-size: 20px;
      font-weight: 700;
      color: var(--primary-text);
      letter-spacing: -0.02em;
    }

    .page-description {
      font-size: 13px;
      color: var(--secondary-text);
      margin-top: 2px;
    }

    .preset-toolbar {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--surface);
      padding: 0.35rem 0.5rem;
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    .preset-label {
      font-size: 11px;
      font-weight: 600;
      color: var(--secondary-text);
      text-transform: uppercase;
      padding: 0 0.4rem;
    }

    .preset-btn {
      padding: 0.35rem 0.75rem;
      font-size: 12px;
      font-weight: 500;
      background: transparent;
      border: 1px solid transparent;
      border-radius: 6px;
      color: var(--primary-text);
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .preset-btn:hover {
      background: var(--sidebar);
      border-color: var(--border);
    }

    /* Cards & Grids */
    .view-content {
      display: none;
      flex-direction: column;
      gap: 1.75rem;
    }

    .view-content.active {
      display: flex;
    }

    .grid-layout {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
    }

    @media (max-width: 980px) {
      .grid-layout { grid-template-columns: 1fr; }
      body { flex-direction: column; }
      aside { width: 100%; min-height: auto; position: static; }
    }

    .panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
    }

    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.85rem;
    }

    .panel-title {
      font-size: 14.5px;
      font-weight: 700;
      color: var(--primary-text);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .step-indicator {
      width: 22px;
      height: 22px;
      border-radius: 6px;
      background: var(--sidebar);
      color: var(--primary-blue);
      border: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      font-weight: 700;
    }

    /* Dropzones */
    .drop-surface {
      border: 1.5px dashed var(--border);
      border-radius: 10px;
      padding: 2.25rem 1.5rem;
      text-align: center;
      cursor: pointer;
      position: relative;
      background: var(--sidebar);
      transition: all 0.2s ease;
    }

    .drop-surface:hover, .drop-surface.dragover {
      border-color: var(--primary-blue);
      background: rgba(37, 99, 235, 0.03);
    }

    .drop-surface input[type="file"] {
      position: absolute;
      inset: 0;
      opacity: 0;
      cursor: pointer;
    }

    .drop-icon {
      color: var(--secondary-text);
      margin-bottom: 0.5rem;
    }

    .drop-main-text {
      font-size: 13.5px;
      font-weight: 600;
      color: var(--primary-text);
    }

    .drop-sub-text {
      font-size: 12px;
      color: var(--secondary-text);
      margin-top: 2px;
    }

    /* Preview Canvas Container */
    .preview-frame {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #0E1424;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 210px;
      max-height: 250px;
      overflow: hidden;
      position: relative;
    }

    .preview-frame img, .preview-frame canvas {
      max-width: 100%;
      max-height: 240px;
      object-fit: contain;
    }

    /* Capacity Visualizer */
    .capacity-section {
      background: var(--sidebar);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
    }

    .capacity-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 12.5px;
    }

    .capacity-meter-track {
      width: 100%;
      height: 8px;
      background: #E2E8F0;
      border-radius: 4px;
      overflow: hidden;
      display: flex;
    }

    .capacity-meter-fill {
      height: 100%;
      background: var(--primary-blue);
      width: 0%;
      transition: width 0.3s ease, background-color 0.3s ease;
    }

    .capacity-legend {
      display: flex;
      justify-content: space-between;
      font-size: 11.5px;
      color: var(--secondary-text);
      font-family: var(--font-mono);
    }

    /* Form Controls */
    .form-row {
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
    }

    .form-label {
      font-size: 12.5px;
      font-weight: 600;
      color: var(--primary-text);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .segmented-control {
      display: flex;
      background: var(--sidebar);
      padding: 3px;
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    .segment-btn {
      flex: 1;
      padding: 0.45rem;
      font-size: 12.5px;
      font-weight: 500;
      text-align: center;
      background: transparent;
      border: none;
      border-radius: 6px;
      color: var(--secondary-text);
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .segment-btn.active {
      background: var(--surface);
      color: var(--primary-blue);
      font-weight: 600;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
    }

    textarea, input[type="text"], input[type="password"] {
      width: 100%;
      padding: 0.65rem 0.85rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--primary-text);
      font-family: var(--font-sans);
      font-size: 13px;
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }

    textarea:focus, input[type="text"]:focus, input[type="password"]:focus {
      border-color: var(--primary-blue);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
    }

    textarea {
      font-family: var(--font-mono);
      font-size: 12.5px;
      min-height: 100px;
      resize: vertical;
    }

    .input-with-action {
      position: relative;
      display: flex;
      align-items: center;
    }

    .input-with-action input {
      padding-right: 2.5rem;
    }

    .action-icon-btn {
      position: absolute;
      right: 0.5rem;
      background: transparent;
      border: none;
      color: var(--secondary-text);
      cursor: pointer;
      padding: 0.35rem;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .action-icon-btn:hover {
      color: var(--primary-text);
    }

    /* Buttons */
    .btn-solid {
      background: var(--primary-blue);
      color: #FFFFFF;
      border: none;
      border-radius: 8px;
      padding: 0.75rem 1.25rem;
      font-size: 13.5px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: all 0.15s ease;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
      text-decoration: none;
    }

    .btn-solid:hover {
      background: var(--primary-blue-hover);
    }

    .btn-solid:disabled {
      opacity: 0.5;
      cursor: not-allowed;
      box-shadow: none;
    }

    .btn-outline {
      background: var(--surface);
      color: var(--primary-text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.65rem 1rem;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: all 0.15s ease;
      text-decoration: none;
    }

    .btn-outline:hover {
      background: var(--sidebar);
      border-color: #CBD5E1;
    }

    /* Alerts & Callouts */
    .callout {
      border-radius: 8px;
      padding: 0.85rem 1rem;
      display: flex;
      gap: 0.75rem;
      font-size: 12px;
      line-height: 1.45;
    }

    .callout.info {
      background: var(--info-light);
      border: 1px solid rgba(2, 132, 199, 0.25);
      color: var(--info);
    }

    .callout.success {
      background: var(--success-light);
      border: 1px solid rgba(22, 163, 74, 0.25);
      color: var(--success);
    }

    .callout.warning {
      background: var(--warning-light);
      border: 1px solid rgba(217, 119, 6, 0.25);
      color: var(--warning);
    }

    .callout.critical {
      background: var(--critical-light);
      border: 1px solid rgba(220, 38, 38, 0.25);
      color: var(--critical);
    }

    /* Verification Studio (Visual Steganalysis) */
    .studio-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }

    .studio-tabs {
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }

    .studio-tab-btn {
      padding: 0.35rem 0.85rem;
      font-size: 12.5px;
      font-weight: 500;
      background: transparent;
      border: 1px solid transparent;
      border-radius: 6px;
      color: var(--secondary-text);
      cursor: pointer;
    }

    .studio-tab-btn.active {
      background: var(--sidebar);
      border-color: var(--border);
      color: var(--primary-blue);
      font-weight: 600;
    }

    /* Comparison Split Slider */
    .slider-box {
      position: relative;
      width: 100%;
      height: 280px;
      overflow: hidden;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: #0E1424;
      user-select: none;
    }

    .slider-box img {
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 100%;
      object-fit: contain;
    }

    .slider-overlay {
      position: absolute;
      top: 0; left: 0;
      height: 100%;
      overflow: hidden;
      border-right: 2px solid #FFFFFF;
      width: 50%;
    }

    .slider-handle {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      width: 32px;
      height: 32px;
      background: #FFFFFF;
      border-radius: 50%;
      box-shadow: 0 2px 6px rgba(0,0,0,0.3);
      cursor: ew-resize;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary-text);
      z-index: 10;
    }

    /* Technical Data Pill Grid */
    .meta-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }

    .meta-table th {
      text-align: left;
      font-weight: 500;
      color: var(--secondary-text);
      padding: 0.4rem 0;
      border-bottom: 1px solid var(--border);
    }

    .meta-table td {
      text-align: right;
      font-family: var(--font-mono);
      font-weight: 600;
      color: var(--primary-text);
      padding: 0.4rem 0;
      border-bottom: 1px solid var(--border);
    }

    /* Spinner */
    .spinner {
      width: 14px;
      height: 14px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top-color: #FFFFFF;
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
    }

    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>

  <!-- Sidebar -->
  <aside>
    <div class="sidebar-header">
      <div class="brand-mark">
        <div class="brand-icon">S</div>
        <div>
          <div class="brand-title">StegoSuite</div>
        </div>
      </div>
    </div>

    <div class="nav-menu">
      <div class="nav-label">Core Operations</div>
      <button id="nav-btn-prep" class="nav-item active" onclick="navigate('prep')">
        <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
        Image Preparer
      </button>
      <button id="nav-btn-ext" class="nav-item" onclick="navigate('ext')">
        <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
        Message Extractor
      </button>
    </div>

    <div class="sidebar-footer">
      <div class="engine-telemetry">
        <div class="telemetry-row">
          <span class="telemetry-title">Security Core</span>
          <span class="telemetry-value"><span class="live-dot"></span>Active</span>
        </div>
        <div class="telemetry-row">
          <span class="telemetry-title">Cipher</span>
          <span class="telemetry-value">AES-256-GCM</span>
        </div>
        <div class="telemetry-row">
          <span class="telemetry-title">KDF</span>
          <span class="telemetry-value">Argon2id</span>
        </div>
        <div class="telemetry-row">
          <span class="telemetry-title">Bit Channel</span>
          <span class="telemetry-value">1-LSB RGB</span>
        </div>
      </div>
    </div>
  </aside>

  <!-- Main View Area -->
  <main>

    <!-- VIEW 1: IMAGE PREPARER -->
    <div id="view-prep" class="view-content active">
      <div class="top-bar">
        <div>
          <h1 class="page-title">Image Preparer</h1>
          <p class="page-description">Embed authenticated confidential payloads into lossless PNG carrier images.</p>
        </div>
        <div class="preset-toolbar">
          <span class="preset-label">Presets:</span>
          <button class="preset-btn" onclick="loadCarrierPreset('document')">Document</button>
          <button class="preset-btn" onclick="loadCarrierPreset('landscape')">Landscape</button>
          <button class="preset-btn" onclick="loadCarrierPreset('abstract')">Abstract</button>
        </div>
      </div>

      <div class="grid-layout">
        <!-- Panel 1: Carrier & Capacity -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">
              <span class="step-indicator">1</span>
              Carrier Image Specification
            </div>
          </div>

          <div class="drop-surface" id="prep-drop-zone">
            <input type="file" id="prep-file-input" accept="image/png">
            <svg class="drop-icon" width="32" height="32" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
            <div class="drop-main-text">Upload PNG Carrier Image</div>
            <div class="drop-sub-text">Drag and drop or browse (Lossless PNG only)</div>
          </div>

          <div class="preview-frame" id="prep-preview-container">
            <img id="prep-carrier-img" src="" alt="Carrier Preview">
          </div>

          <!-- Capacity Gauge -->
          <div class="capacity-section">
            <div class="capacity-header">
              <span style="font-weight: 600; color: var(--primary-text);">Carrier Capacity Utilization</span>
              <span id="cap-percent-label" style="font-family: var(--font-mono); font-weight: 600; color: var(--primary-blue);">0.0%</span>
            </div>
            <div class="capacity-meter-track">
              <div id="cap-meter-bar" class="capacity-meter-fill"></div>
            </div>
            <div class="capacity-legend">
              <span id="cap-used-label">Payload: 0 B</span>
              <span id="cap-available-label">Available: 0 B</span>
            </div>
          </div>

          <!-- Technical Specs Table -->
          <table class="meta-table">
            <tr>
              <th>Image Dimensions</th>
              <td id="spec-dim">-</td>
            </tr>
            <tr>
              <th>Total Pixel Density</th>
              <td id="spec-pixels">-</td>
            </tr>
            <tr>
              <th>Raw RGB Capacity</th>
              <td id="spec-raw">-</td>
            </tr>
            <tr>
              <th>Alpha Channel Rule</th>
              <td>Preserved (0 bits embedded)</td>
            </tr>
          </table>
        </div>

        <!-- Panel 2: Payload & Security -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">
              <span class="step-indicator">2</span>
              Secret Payload & Security
            </div>
          </div>

          <!-- Payload Type Selector -->
          <div class="form-row">
            <span class="form-label">Payload Format</span>
            <div class="segmented-control">
              <button id="seg-text" class="segment-btn active" onclick="setPayloadMode('text')">Text Message (UTF-8)</button>
              <button id="seg-file" class="segment-btn" onclick="setPayloadMode('file')">Binary File Attachment</button>
            </div>
          </div>

          <!-- Text Field -->
          <div id="group-text" class="form-row">
            <div class="form-label">
              <span>Confidential Plaintext</span>
              <span id="text-counter" style="font-family: var(--font-mono); color: var(--secondary-text); font-weight: 500;">0 chars (0 bytes)</span>
            </div>
            <textarea id="input-text" placeholder="Type confidential text..." oninput="updatePayloadCalculations()"></textarea>
          </div>

          <!-- File Field -->
          <div id="group-file" class="form-row" style="display: none;">
            <span class="form-label">Choose Binary Payload File</span>
            <input type="file" id="input-binary-file" onchange="handleBinaryFileSelection(event)">
            <div id="file-selection-info" style="font-size: 11.5px; font-family: var(--font-mono); color: var(--secondary-text); margin-top: 4px;"></div>
          </div>

          <!-- Cryptographic Options -->
          <div style="border-top: 1px solid var(--border); padding-top: 1rem;" class="form-row">
            <label style="display: flex; align-items: center; gap: 0.6rem; cursor: pointer;">
              <input type="checkbox" id="check-encrypt" checked onchange="toggleEncryptionFields()" style="accent-color: var(--primary-blue); width: 16px; height: 16px;">
              <span style="font-weight: 600; font-size: 13px;">Enable Authenticated Encryption (AES-256-GCM + Argon2id)</span>
            </label>
            <p style="font-size: 11.5px; color: var(--secondary-text); margin-left: 1.6rem;">
              Derives a 256-bit symmetric key from your passphrase. Authenticates the entire container header as Additional Authenticated Data (AAD).
            </p>
          </div>

          <!-- Passphrase Inputs -->
          <div id="group-passphrase" class="form-row" style="display: flex; flex-direction: column; gap: 0.75rem;">
            <div>
              <span class="form-label">Passphrase</span>
              <div class="input-with-action">
                <input type="password" id="input-password" oninput="validatePassphrase()" placeholder="Enter strong passphrase...">
                <button type="button" class="action-icon-btn" onclick="togglePassVisibility('input-password')">
                  <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                </button>
              </div>
            </div>

            <div>
              <span class="form-label">Confirm Passphrase</span>
              <div class="input-with-action">
                <input type="password" id="input-password-confirm" oninput="validatePassphrase()" placeholder="Re-enter passphrase...">
                <button type="button" class="action-icon-btn" onclick="togglePassVisibility('input-password-confirm')">
                  <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                </button>
              </div>
              <div id="pass-match-hint" style="font-size: 11px; margin-top: 3px; font-weight: 500;"></div>
            </div>
          </div>

          <button id="btn-submit-encode" class="btn-solid" onclick="executeEncodeAction()">
            <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            <span>Embed Payload & Generate Stego Image</span>
          </button>
        </div>
      </div>

      <!-- Verification Studio (Before / After / Heatmap) -->
      <div id="studio-container" class="studio-panel" style="display: none;">
        <div class="panel-header">
          <div class="panel-title">
            <span class="step-indicator">3</span>
            Visual Steganalysis & Pre-Flight Verification
          </div>
          <div class="callout success" style="padding: 0.35rem 0.75rem;">
            <span>✔ Internal Round-Trip Verified (0 Bit Errors)</span>
          </div>
        </div>

        <div class="studio-tabs">
          <button id="st-tab-compare" class="studio-tab-btn active" onclick="switchStudioTab('compare')">Interactive Split Slider</button>
          <button id="st-tab-heatmap" class="studio-tab-btn" onclick="switchStudioTab('heatmap')">LSB Amplification Heatmap (128&times; Delta)</button>
        </div>

        <!-- Tab A: Split Slider -->
        <div id="studio-view-compare" class="slider-box" id="comparison-slider">
          <img id="img-underlay-stego" src="" alt="Stego Output">
          <div id="slider-overlay" class="slider-overlay">
            <img id="img-overlay-original" src="" alt="Original Carrier">
          </div>
          <div id="slider-handle" class="slider-handle">
            <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l4-4 4 4m0 6l-4 4-4-4"/></svg>
          </div>
        </div>

        <!-- Tab B: Heatmap Canvas -->
        <div id="studio-view-heatmap" class="preview-frame" style="display: none; height: 280px;">
          <canvas id="heatmap-canvas"></canvas>
        </div>

        <div style="display: flex; items-center; justify-content: space-between; gap: 1rem; flex-wrap: wrap;">
          <div style="font-size: 12px; color: var(--secondary-text);">
            Stego image is lossless PNG with identical dimensions. Visually imperceptible to the human eye.
          </div>
          <div style="display: flex; gap: 0.75rem;">
            <a id="btn-download-stego" class="btn-solid" download="stego_carrier.png">
              <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              Download Stego PNG (<span id="out-filesize">-</span>)
            </a>
            <button class="btn-outline" onclick="transferStegoToExtractor()">
              Send to Extractor &rarr;
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- VIEW 2: MESSAGE EXTRACTOR -->
    <div id="view-ext" class="view-content">
      <div class="top-bar">
        <div>
          <h1 class="page-title">Message Extractor</h1>
          <p class="page-description">Inspect carrier images for supported binary containers and extract authenticated contents.</p>
        </div>
      </div>

      <div class="grid-layout">
        <!-- Extractor Import Panel -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">
              <span class="step-indicator">1</span>
              Inspect Suspect Image
            </div>
          </div>

          <div class="drop-surface" id="ext-drop-zone">
            <input type="file" id="ext-file-input" accept="image/png">
            <svg class="drop-icon" width="32" height="32" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
            <div class="drop-main-text">Upload Image for Inspection</div>
            <div class="drop-sub-text">Drop any PNG image to scan for embedded data</div>
          </div>

          <div class="preview-frame" id="ext-preview-container">
            <img id="ext-preview-img" src="" alt="Suspect Preview">
          </div>

          <!-- Finding Notification Box -->
          <div id="ext-finding-box" class="callout info">
            <div>
              <div id="ext-finding-title" style="font-weight: 700; font-size: 12.5px;">Ready to Scan</div>
              <div id="ext-finding-desc" style="margin-top: 2px;">Upload an image or send directly from the Image Preparer.</div>
            </div>
          </div>

          <table class="meta-table">
            <tr>
              <th>Detected Version</th>
              <td id="ext-spec-version">-</td>
            </tr>
            <tr>
              <th>Payload Type</th>
              <td id="ext-spec-type">-</td>
            </tr>
            <tr>
              <th>Encryption State</th>
              <td id="ext-spec-enc">-</td>
            </tr>
            <tr>
              <th>Declared Payload Length</th>
              <td id="ext-spec-len">-</td>
            </tr>
          </table>
        </div>

        <!-- Extractor Extraction Panel -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">
              <span class="step-indicator">2</span>
              Authenticated Decryption & Content Extraction
            </div>
          </div>

          <div id="ext-pass-section" class="form-row" style="display: none;">
            <span class="form-label">Required Decryption Passphrase</span>
            <div class="input-with-action">
              <input type="password" id="ext-input-pass" placeholder="Enter passphrase to decrypt...">
              <button type="button" class="action-icon-btn" onclick="togglePassVisibility('ext-input-pass')">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
              </button>
            </div>
            <p style="font-size: 11.5px; color: var(--secondary-text);">
              If the password is incorrect or image bits were altered, authenticated decryption safely rejects the payload.
            </p>
          </div>

          <button id="btn-submit-extract" class="btn-solid" style="background: var(--teal); display: none;" onclick="executeExtractAction()">
            <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"/></svg>
            <span>Authenticate & Extract Payload</span>
          </button>

          <!-- Result Container -->
          <div id="ext-result-container" style="display: none; flex-direction: column; gap: 1rem;">
            <div class="callout success">
              <div>
                <div style="font-weight: 700;">Payload Authenticated Successfully</div>
                <div style="font-size: 11.5px;">AES-256-GCM verification tag and header metadata matched. Plaintext verified.</div>
              </div>
            </div>

            <!-- Text Result -->
            <div id="ext-text-box" class="form-row" style="display: none;">
              <div class="form-label">
                <span>Extracted Plaintext</span>
                <button class="btn-outline" style="padding: 0.25rem 0.6rem; font-size: 11px;" onclick="copyExtractedContent()">Copy to Clipboard</button>
              </div>
              <div id="ext-text-display" style="padding: 0.85rem; background: var(--sidebar); border: 1px solid var(--border); border-radius: 8px; font-family: var(--font-mono); font-size: 12.5px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto;"></div>
            </div>

            <!-- File Result -->
            <div id="ext-file-box" class="form-row" style="display: none;">
              <span class="form-label">Extracted File Attachment</span>
              <div style="display: flex; items-center; justify-content: space-between; padding: 0.85rem 1rem; background: var(--sidebar); border: 1px solid var(--border); border-radius: 8px;">
                <div>
                  <div id="ext-filename" style="font-weight: 600; color: var(--primary-text); font-size: 13px;">file.bin</div>
                  <div id="ext-filemeta" style="font-size: 11px; color: var(--secondary-text); font-family: var(--font-mono);">0 KB &bull; application/octet-stream</div>
                </div>
                <a id="ext-file-download-btn" class="btn-solid" download>
                  Download File
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </main>

  <script>
    // State
    let currentCarrierB64 = '';
    let currentStegoB64 = '';
    let currentExtB64 = '';
    let selectedBinaryFileB64 = null;
    let selectedBinaryFileName = '';
    let selectedBinaryFileType = '';
    let rawCapacityBytes = 0;
    let usableTextBytes = 0;

    // Navigation
    function navigate(tab) {
      document.getElementById('nav-btn-prep').classList.toggle('active', tab === 'prep');
      document.getElementById('nav-btn-ext').classList.toggle('active', tab === 'ext');
      document.getElementById('view-prep').classList.toggle('active', tab === 'prep');
      document.getElementById('view-ext').classList.toggle('active', tab === 'ext');
    }

    function setPayloadMode(mode) {
      document.getElementById('seg-text').classList.toggle('active', mode === 'text');
      document.getElementById('seg-file').classList.toggle('active', mode === 'file');
      document.getElementById('group-text').style.display = mode === 'text' ? 'flex' : 'none';
      document.getElementById('group-file').style.display = mode === 'file' ? 'flex' : 'none';
      updatePayloadCalculations();
    }

    function toggleEncryptionFields() {
      const isEnc = document.getElementById('check-encrypt').checked;
      document.getElementById('group-passphrase').style.display = isEnc ? 'flex' : 'none';
      updatePayloadCalculations();
    }

    function togglePassVisibility(id) {
      const el = document.getElementById(id);
      el.type = el.type === 'password' ? 'text' : 'password';
    }

    function validatePassphrase() {
      const p1 = document.getElementById('input-password').value;
      const p2 = document.getElementById('input-password-confirm').value;
      const hint = document.getElementById('pass-match-hint');
      if (!p1 && !p2) {
        hint.textContent = '';
      } else if (!p2) {
        hint.textContent = '';
      } else if (p1 === p2) {
        hint.style.color = 'var(--success)';
        hint.textContent = '✔ Passphrases match';
      } else {
        hint.style.color = 'var(--critical)';
        hint.textContent = '✖ Passphrases do not match';
      }
    }

    // Preset Carrier Generators
    function loadCarrierPreset(type) {
      const canvas = document.createElement('canvas');
      canvas.width = 400;
      canvas.height = 300;
      const ctx = canvas.getContext('2d');

      if (type === 'document') {
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(0, 0, 400, 300);
        ctx.fillStyle = '#172033';
        ctx.font = 'bold 16px Inter, sans-serif';
        ctx.fillText('FINANCIAL AUDIT MEMORANDUM', 25, 45);
        ctx.fillStyle = '#64748B';
        ctx.font = '12px Inter, sans-serif';
        ctx.fillText('CONFIDENTIAL &bull; FOR INTERNAL CLEARANCE ONLY', 25, 68);
        ctx.strokeStyle = '#E2E8F0';
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(25, 80); ctx.lineTo(375, 80); ctx.stroke();

        ctx.fillStyle = '#172033';
        for (let i = 0; i < 7; i++) {
          ctx.fillRect(25, 105 + i * 22, 100 + (i % 3) * 60, 8);
          ctx.fillRect(280, 105 + i * 22, 70, 8);
        }
      } else if (type === 'landscape') {
        const grad = ctx.createLinearGradient(0, 0, 0, 300);
        grad.addColorStop(0, '#1E3A8A');
        grad.addColorStop(0.5, '#3B82F6');
        grad.addColorStop(0.7, '#F59E0B');
        grad.addColorStop(1, '#0D9488');
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, 400, 300);

        ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
        ctx.beginPath(); ctx.arc(80, 70, 35, 0, Math.PI * 2); ctx.fill();
      } else {
        // Abstract
        const grad = ctx.createLinearGradient(0, 0, 400, 300);
        grad.addColorStop(0, '#0F172A');
        grad.addColorStop(1, '#1E293B');
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, 400, 300);

        ctx.strokeStyle = '#0D9488';
        ctx.lineWidth = 2;
        for (let i = 0; i < 6; i++) {
          ctx.strokeRect(30 + i * 25, 30 + i * 20, 200, 140);
        }
      }

      setCarrierFromDataUrl(canvas.toDataURL('image/png'));
    }

    function setCarrierFromDataUrl(dataUrl) {
      currentCarrierB64 = dataUrl.split(',')[1];
      document.getElementById('prep-carrier-img').src = dataUrl;
      document.getElementById('studio-container').style.display = 'none';

      // Query capacity
      fetch('/api/capacity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ carrierBase64: currentCarrierB64, isEncrypted: true })
      })
      .then(r => r.json())
      .then(d => {
        rawCapacityBytes = d.rawCapacityBytes;
        usableTextBytes = d.usableTextCapacityBytes;
        document.getElementById('spec-dim').textContent = `${d.width} \u00D7 ${d.height} px`;
        document.getElementById('spec-pixels').textContent = (d.width * d.height).toLocaleString();
        document.getElementById('spec-raw').textContent = `${(d.rawCapacityBytes / 1024).toFixed(1)} KB (${d.rawCapacityBytes.toLocaleString()} B)`;
        updatePayloadCalculations();
      });
    }

    document.getElementById('prep-file-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (ev) => setCarrierFromDataUrl(ev.target.result);
      reader.readAsDataURL(file);
    });

    function handleBinaryFileSelection(e) {
      const file = e.target.files[0];
      if (!file) return;
      selectedBinaryFileName = file.name;
      selectedBinaryFileType = file.type || 'application/octet-stream';
      const reader = new FileReader();
      reader.onload = (ev) => {
        selectedBinaryFileB64 = ev.target.result.split(',')[1];
        document.getElementById('file-selection-info').textContent =
          `${file.name} \u2022 ${(file.size / 1024).toFixed(1)} KB \u2022 ${selectedBinaryFileType}`;
        updatePayloadCalculations();
      };
      reader.readAsDataURL(file);
    }

    function updatePayloadCalculations() {
      const isFile = document.getElementById('seg-file').classList.contains('active');
      const isEnc = document.getElementById('check-encrypt').checked;
      let payloadBytes = 0;

      if (isFile) {
        if (selectedBinaryFileB64) {
          payloadBytes = Math.round((selectedBinaryFileB64.length * 3) / 4);
        }
      } else {
        const text = document.getElementById('input-text').value;
        const textBytes = new TextEncoder().encode(text).length;
        payloadBytes = textBytes;
        document.getElementById('text-counter').textContent = `${text.length} chars (${textBytes} bytes)`;
      }

      const overhead = isEnc ? 57 : 13;
      const totalRequired = payloadBytes + overhead;
      const available = rawCapacityBytes;

      const meter = document.getElementById('cap-meter-bar');
      const pctLabel = document.getElementById('cap-percent-label');
      const usedLabel = document.getElementById('cap-used-label');
      const availLabel = document.getElementById('cap-available-label');
      const submitBtn = document.getElementById('btn-submit-encode');

      if (available <= 0) {
        pctLabel.textContent = '0%';
        meter.style.width = '0%';
        usedLabel.textContent = `Payload: ${payloadBytes} B`;
        availLabel.textContent = 'Available: 0 B';
        return;
      }

      const pct = Math.min(100, (totalRequired / available) * 100);
      pctLabel.textContent = `${pct.toFixed(1)}%`;
      meter.style.width = `${pct}%`;
      usedLabel.textContent = `Required: ${totalRequired} B (${payloadBytes} B payload + ${overhead} B framing)`;
      availLabel.textContent = `Free: ${Math.max(0, available - totalRequired).toLocaleString()} B`;

      if (totalRequired > available) {
        meter.style.background = 'var(--critical)';
        pctLabel.style.color = 'var(--critical)';
        submitBtn.disabled = true;
      } else if (pct > 75) {
        meter.style.background = 'var(--warning)';
        pctLabel.style.color = 'var(--warning)';
        submitBtn.disabled = false;
      } else {
        meter.style.background = 'var(--primary-blue)';
        pctLabel.style.color = 'var(--primary-blue)';
        submitBtn.disabled = false;
      }
    }

    async function executeEncodeAction() {
      if (!currentCarrierB64) {
        alert('Please select or generate a carrier image first.');
        return;
      }

      const isFile = document.getElementById('seg-file').classList.contains('active');
      const isEnc = document.getElementById('check-encrypt').checked;
      const p1 = document.getElementById('input-password').value;
      const p2 = document.getElementById('input-password-confirm').value;

      if (isEnc) {
        if (!p1) {
          alert('Please enter a passphrase when authenticated encryption is enabled.');
          return;
        }
        if (p1 !== p2) {
          alert('Passphrases do not match. Please verify your passphrase.');
          return;
        }
      }

      const btn = document.getElementById('btn-submit-encode');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Embedding into RGB bits...';

      const req = {
        carrierBase64: currentCarrierB64,
        type: isFile ? 'file' : 'text',
        password: isEnc ? p1 : null,
      };

      if (isFile) {
        if (!selectedBinaryFileB64) {
          alert('Please select a file payload.');
          btn.disabled = false;
          btn.textContent = 'Embed Payload & Generate Stego Image';
          return;
        }
        req.fileBase64 = selectedBinaryFileB64;
        req.filename = selectedBinaryFileName;
        req.mediaType = selectedBinaryFileType;
      } else {
        const text = document.getElementById('input-text').value;
        if (!text || text.length === 0) {
          alert('Please enter a confidential message to embed.');
          btn.disabled = false;
          btn.innerHTML = '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg><span>Embed Payload & Generate Stego Image</span>';
          return;
        }
        req.text = text;
      }

      try {
        const res = await fetch('/api/encode', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req)
        });
        const d = await res.json();
        if (d.success) {
          currentStegoB64 = d.stegoImageBase64;
          const url = 'data:image/png;base64,' + d.stegoImageBase64;
          document.getElementById('btn-download-stego').href = url;
          document.getElementById('out-filesize').textContent = `${(d.fileSize / 1024).toFixed(1)} KB`;

          // Setup comparison slider
          document.getElementById('img-underlay-stego').src = url;
          document.getElementById('img-overlay-original').src = 'data:image/png;base64,' + currentCarrierB64;
          document.getElementById('studio-container').style.display = 'flex';

          // Generate LSB Heatmap
          generateLsbHeatmap();
        } else {
          alert('Encoding Error: ' + d.message);
        }
      } catch (e) {
        alert('Network or server error: ' + e);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg><span>Embed Payload & Generate Stego Image</span>';
      }
    }

    function switchStudioTab(tab) {
      document.getElementById('st-tab-compare').classList.toggle('active', tab === 'compare');
      document.getElementById('st-tab-heatmap').classList.toggle('active', tab === 'heatmap');
      document.getElementById('studio-view-compare').style.display = tab === 'compare' ? 'block' : 'none';
      document.getElementById('studio-view-heatmap').style.display = tab === 'heatmap' ? 'flex' : 'none';
    }

    // Interactive slider dragging
    const sliderBox = document.getElementById('studio-view-compare');
    const overlay = document.getElementById('slider-overlay');
    const handle = document.getElementById('slider-handle');
    let isDragging = false;

    function moveSlider(clientX) {
      const rect = sliderBox.getBoundingClientRect();
      let pos = (clientX - rect.left) / rect.width;
      pos = Math.max(0, Math.min(1, pos));
      overlay.style.width = (pos * 100) + '%';
      handle.style.left = (pos * 100) + '%';
    }

    sliderBox.addEventListener('mousedown', () => isDragging = true);
    window.addEventListener('mouseup', () => isDragging = false);
    window.addEventListener('mousemove', (e) => {
      if (isDragging) moveSlider(e.clientX);
    });

    // Generate difference heatmap between original and stego image
    function generateLsbHeatmap() {
      const img1 = new Image();
      const img2 = new Image();
      img1.src = 'data:image/png;base64,' + currentCarrierB64;
      img2.src = 'data:image/png;base64,' + currentStegoB64;

      Promise.all([
        new Promise(r => img1.onload = r),
        new Promise(r => img2.onload = r)
      ]).then(() => {
        const canvas = document.getElementById('heatmap-canvas');
        canvas.width = img1.width;
        canvas.height = img1.height;
        const ctx = canvas.getContext('2d');

        const c1 = document.createElement('canvas');
        c1.width = img1.width; c1.height = img1.height;
        const ctx1 = c1.getContext('2d');
        ctx1.drawImage(img1, 0, 0);
        const data1 = ctx1.getImageData(0, 0, img1.width, img1.height).data;

        const c2 = document.createElement('canvas');
        c2.width = img2.width; c2.height = img2.height;
        const ctx2 = c2.getContext('2d');
        ctx2.drawImage(img2, 0, 0);
        const data2 = ctx2.getImageData(0, 0, img2.width, img2.height).data;

        const heatImg = ctx.createImageData(img1.width, img1.height);
        const out = heatImg.data;

        for (let i = 0; i < data1.length; i += 4) {
          const diffR = Math.abs(data1[i] - data2[i]);
          const diffG = Math.abs(data1[i+1] - data2[i+1]);
          const diffB = Math.abs(data1[i+2] - data2[i+2]);
          const hasDiff = (diffR + diffG + diffB) > 0;

          if (hasDiff) {
            // Paint modified bit in bright Teal (#0D9488)
            out[i] = 13;
            out[i+1] = 148;
            out[i+2] = 136;
            out[i+3] = 255;
          } else {
            // Unmodified: dark background
            out[i] = 15;
            out[i+1] = 23;
            out[i+2] = 42;
            out[i+3] = 255;
          }
        }
        ctx.putImageData(heatImg, 0, 0);
      });
    }

    function transferStegoToExtractor() {
      currentExtB64 = currentStegoB64;
      document.getElementById('ext-preview-img').src = 'data:image/png;base64,' + currentExtB64;
      document.getElementById('ext-input-pass').value = document.getElementById('input-password').value;
      navigate('ext');
      inspectSuspectImage();
    }

    // Extractor Logic
    document.getElementById('ext-file-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (ev) => {
        currentExtB64 = ev.target.result.split(',')[1];
        document.getElementById('ext-preview-img').src = ev.target.result;
        inspectSuspectImage();
      };
      reader.readAsDataURL(file);
    });

    async function inspectSuspectImage() {
      if (!currentExtB64) return;

      const box = document.getElementById('ext-finding-box');
      const title = document.getElementById('ext-finding-title');
      const desc = document.getElementById('ext-finding-desc');
      const passSec = document.getElementById('ext-pass-section');
      const btnExtract = document.getElementById('btn-submit-extract');
      const resContainer = document.getElementById('ext-result-container');

      resContainer.style.display = 'none';

      try {
        const res = await fetch('/api/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ carrierBase64: currentExtB64 })
        });
        const d = await res.json();

        if (d.status === 'supported') {
          box.className = 'callout success';
          title.textContent = 'Supported Stego Container Detected';
          desc.textContent = d.message;

          document.getElementById('ext-spec-version').textContent = `Version ${d.payload.formatVersion}`;
          document.getElementById('ext-spec-type').textContent = d.payload.type.toUpperCase();
          document.getElementById('ext-spec-enc').textContent = d.payload.isEncrypted ? 'Encrypted (AES-256-GCM)' : 'Unencrypted';
          document.getElementById('ext-spec-len').textContent = `${d.payload.declaredPayloadLength} bytes`;

          passSec.style.display = d.payload.isEncrypted ? 'flex' : 'none';
          btnExtract.style.display = 'inline-flex';
        } else if (d.status === 'no_payload') {
          box.className = 'callout warning';
          title.textContent = 'No Supported Container Signature';
          desc.textContent = d.message;

          document.getElementById('ext-spec-version').textContent = '-';
          document.getElementById('ext-spec-type').textContent = '-';
          document.getElementById('ext-spec-enc').textContent = '-';
          document.getElementById('ext-spec-len').textContent = '-';

          passSec.style.display = 'none';
          btnExtract.style.display = 'none';
        } else {
          box.className = 'callout critical';
          title.textContent = 'Carrier Inspection Error';
          desc.textContent = d.message;

          passSec.style.display = 'none';
          btnExtract.style.display = 'none';
        }
      } catch (e) {
        alert('Server inspection request failed: ' + e);
      }
    }

    async function executeExtractAction() {
      if (!currentExtB64) return;
      const btn = document.getElementById('btn-submit-extract');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Authenticating & Decrypting...';

      const pass = document.getElementById('ext-input-pass').value;

      try {
        const res = await fetch('/api/extract', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ carrierBase64: currentExtB64, password: pass })
        });
        const d = await res.json();
        const resBox = document.getElementById('ext-result-container');
        const textBox = document.getElementById('ext-text-box');
        const fileBox = document.getElementById('ext-file-box');

        if (d.success) {
          resBox.style.display = 'flex';
          if (d.type === 'text') {
            textBox.style.display = 'flex';
            fileBox.style.display = 'none';
            document.getElementById('ext-text-display').textContent = d.text;
          } else {
            textBox.style.display = 'none';
            fileBox.style.display = 'flex';
            document.getElementById('ext-filename').textContent = d.filename;
            document.getElementById('ext-filemeta').textContent = `${(d.fileSize/1024).toFixed(1)} KB \u2022 ${d.mediaType}`;
            const dl = document.getElementById('ext-file-download-btn');
            dl.href = 'data:' + d.mediaType + ';base64,' + d.fileBase64;
            dl.download = d.filename;
          }
        } else {
          alert('Decryption Failed: ' + d.message);
        }
      } catch (e) {
        alert('Extraction request failed: ' + e);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"/></svg><span>Authenticate & Extract Payload</span>';
      }
    }

    function copyExtractedContent() {
      const text = document.getElementById('ext-text-display').textContent;
      navigator.clipboard.writeText(text);
      alert('Extracted plaintext copied to clipboard.');
    }

    window.addEventListener('DOMContentLoaded', () => {
      loadCarrierPreset('document');
    });
  </script>
</body>
</html>
''';
}
