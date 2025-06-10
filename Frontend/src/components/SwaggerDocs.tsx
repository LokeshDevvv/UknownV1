import React from 'react';
import SwaggerUI from 'swagger-ui-react';
import 'swagger-ui-react/swagger-ui.css';
import '@/styles/swagger-custom.css';

const SwaggerDocs: React.FC = () => {
  return (
    <div className="bg-[#212121] rounded-lg overflow-hidden">
      <SwaggerUI url="http://localhost:5000/api/swagger.json" />
    </div>
  );
};

export default SwaggerDocs; 