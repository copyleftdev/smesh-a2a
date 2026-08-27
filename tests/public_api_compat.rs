use smesh_a2a::MeshRequest;

#[test]
fn downstream_mesh_request_struct_literal_remains_source_compatible() {
    let request = MeshRequest {
        protocol: "a2a-v1".to_owned(),
        task_id: "task-1".to_owned(),
        context_id: "context-1".to_owned(),
        text: "hello".to_owned(),
    };
    assert_eq!(request.task_id, "task-1");
}
