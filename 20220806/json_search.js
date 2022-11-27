var all_cities = json.Places.filter(function(item, index){
  if (item.Type == "City" ) return true;
});
for( var i = 0; i < all_cities.length; i++ ){
  console.log(all_cities[i].Name);
}
