from app import create_app

application = create_app()

if __name__ == "__main__":
    print("=" * 60)
    print("  AI Web Vulnerability Scanner — Educational Lab Tool")
    print("  Running at: http://localhost:8080")
    print("  WARNING: Test only against authorized local targets!")
    print("=" * 60)
    application.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
