use std::io::Result;

fn main() -> Result<()> {
    protobuf_codegen::Codegen::new()
        // Use `protoc` parser, optional.
        .protoc()
        // All inputs and imports from the inputs must reside in `includes`
        // directories.
        .includes(["src/"])
        // Inputs must reside in some of include paths.
        .input("src/pwdb.proto")
        // Specify output directory relative to Cargo output directory.
        .cargo_out_dir("protos")
        .run_from_script();

    Ok(())
}
