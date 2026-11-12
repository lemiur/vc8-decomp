// Fixture unit with an upper-case extension.
struct Shape {
    int sides;
    int Sides() const;
};

// match: 0x00401200 0
int Shape::Sides() const { return sides; }
