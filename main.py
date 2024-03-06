from flask import Flask,request,jsonify
import requests
import json
from bson import json_util
from pymongo import MongoClient
from apscheduler.schedulers.background import BackgroundScheduler
app = Flask(__name__)

client = MongoClient('mongodb://localhost:27017/')
db = client['dem']
collection = db['demo']

def fetchdata():    
    print("Scheduler running")
    resultsperpage = 50
    startIndex = 0
    collection.delete_many({})
    while True:
        try:
            base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
            query_params = {
                'resultsperpage': resultsperpage,
                'startindex': startIndex
            }
            response = requests.get(base_url, params=query_params)
            print(response.status_code, "response code")
            if response.status_code == 200 and response.content:
                data = response.json()
                insertingdata = data['vulnerabilities']
                json_data = json_util.loads(json_util.dumps(insertingdata))
                collection.insert_many(json_data)
                print(" 50 data inserted")
                if len(data) <= 0:
                    break  
                else:
                    startIndex += resultsperpage
                    
        except Exception as e:
            print("An error occurred:", e)
@app.route('/cve', methods=['GET'])
def get_cve_details():
    cve_id = request.args.get('cve_id')
    base_score = request.args.get('base_score')
    lastmodified = request.args.get('last_modified')
    query = {}
    if cve_id:
        query['cve.id'] = cve_id
    if base_score:
        query['cve.metrics.cvssMetricV2.cvssData.baseScore'] = float(base_score)
    if lastmodified:
        query['cve.lastModified'] = lastmodified 
    cves = list(collection.find(query, {'_id': 0}))
    return jsonify(cves)
scheduler = BackgroundScheduler()
scheduler.add_job(fetchdata, 'cron', hour=10, minute=0)
scheduler.start()
if __name__ =='__main__':  
    app.run(debug = True)  