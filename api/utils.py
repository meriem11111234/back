import requests
def fetch_product_from_open_food_facts(barcode):
    url = f"https://world.openfoodfacts.org/api/v0/product/{barcode}.json"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 1:  # Product found
            product_data = data['product']
            return {
                'name': product_data.get('product_name', ''),
                'brand': product_data.get('brands', ''),
                'category': product_data.get('categories', ''),
                'nutritional_info': product_data.get('nutriments', {}),
                'picture': product_data.get('image_url', ''),
            }
    return None
