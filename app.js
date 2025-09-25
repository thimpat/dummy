def retrieve_context(local_path: str, task: str) -> str:
    print(f"[RAG] Querying context for task: {task}")
    documents = SimpleDirectoryReader(local_path).load_data()
    embed_model = HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")
    index = VectorStoreIndex.from_documents(documents, embed_model=embed_model)
    query_engine = index.as_query_engine(llm=Ollama(model="deepseek-coder"))
    response = query_engine.query(task)
    print(f"[RAG] Retrieved context:\n{response}")
    return str(response)

    