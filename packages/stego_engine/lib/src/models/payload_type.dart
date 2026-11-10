/// Identifies the type of payload embedded in a container.
enum PayloadType {
  /// Plain text encoded as UTF-8.
  text(1),

  /// Binary file with associated filename and media type metadata.
  file(2);

  final int id;
  const PayloadType(this.id);

  /// Resolves a numeric byte ID to a [PayloadType].
  ///
  /// Returns `null` if the ID is unknown or unsupported.
  static PayloadType? fromId(int id) {
    for (final type in PayloadType.values) {
      if (type.id == id) return type;
    }
    return null;
  }
}

