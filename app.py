from flask import Flask, request, render_template
from pd_module import check_url, log_result

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    url = request.form.get('url')
    if not url:
        return render_template('index.html', result="No URL provided")

    result = check_url(url)
    log_result(url, result)
    return render_template('index.html', result=f"URL: {url} is {result}")

if __name__ == '__main__':
    app.run(debug=True)
