    ymaps.ready(init);
    function init(){
        var myMap = new ymaps.Map("map", {
            center: {{ map_coords }},
            zoom: {{ zoom }}
        });
            myMap.controls.remove('trafficControl');
            myMap.controls.remove('typeSelector');
            myMap.controls.remove('geolocationControl');
            myMap.controls.remove('searchControl');
            myMap.controls.remove('fullscreenControl');
            myMap.controls.remove('rulerControl');
            {% if point_coords %}
            var properties = {
                balloonContentHeader: '<a href="/map?ll={{ point_coords[0] }},{{ point_coords[1] }}">{{ point_coords[0] }}, {{ point_coords[1] }}</a>',
                balloonContent: '<div style="margin-top: 30px; margin-bottom: 10px; margin-left: 5px;"><a role="button" class="btn btn-outline-primary" href="/posts?ll={{ point_coords[0] }},{{ point_coords[1] }}">Посты</a>&ensp;<a role="button" class="btn btn-secondary" href="/chats?ll={{ point_coords[0] }},{{ point_coords[1] }}">Чаты</a></div>',
                balloonContentFooter: 'Постов: {{ number_of_posts }}, Чатов: {{ number_of_chats }}'
            }
               var myPlacemark = new ymaps.GeoObject({
                    geometry: {
                    type: "Point",
                    coordinates: {{ point_coords }}
                    },
                    properties: properties
                });
                myMap.geoObjects.add(myPlacemark);
            {% endif %}
            myMap.events.add('click', function (e) {
                var coords = e.get('coords').join(',');
                var zoom = myMap.getZoom();
                link = '/map?ll=' + coords + '&z=' + zoom;
                document.location.href = link;
            });
        }