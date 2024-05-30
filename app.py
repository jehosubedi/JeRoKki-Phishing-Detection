from flask import Flask, request, render_template
from pd_module import check_url, log_result

app = Flask(__name__)

results_summary = {
    "Blacklisted": 0,
    "Suspicious": 0,
    "Unreachable": 0,
    "Safe": 0
}

@app.route('/')
def home():
    return render_template('index.html', summary=results_summary)

@app.route('/check', methods=['POST'])
def check():
    url = request.form.get('url')
    if not url:
        return render_template('index.html', result="No URL provided", summary=results_summary)

    result = check_url(url)
    log_result(url, result)
    results_summary[result] += 1
    return render_template('index.html', result=f"URL: {url} is {result}", summary=results_summary)

if __name__ == '__main__':
    app.run(debug=True)
