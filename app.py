from jwt_info_gen import app, generate_jwt_with_info

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
