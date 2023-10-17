fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .out_dir("src/disco")
        .compile(
            &["proto/server.proto"], 
            &[""]
        ).unwrap();
    //tonic_build::compile_protos("proto/server.proto")?;
    Ok(())
}


/* 
tonic_build::configure()
        .build_server(false)
        //.out_dir("src/google")  // you can change the generated code's location
        .compile(
            &["proto/googleapis/google/pubsub/v1/pubsub.proto"],
            &["proto/googleapis"], // specify the root location to search proto dependencies
        ).unwrap();

*/